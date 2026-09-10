import Foundation
import PassKit

// Call from PassKit's generateRequestWithCertificateChain delegate callback.
// endpoint is the HTTPS /v1/cards/{card_id}/apple-wallet/provision URL.
// Reuse requestID only when retrying the exact same challenge.
func fetchProvisioningRequest(
    endpoint: URL, accessToken: String, requestID: UUID,
    certificates: [Data], nonce: Data, nonceSignature: Data
) async throws -> PKAddPaymentPassRequest {
    struct Challenge: Encodable {
        let certificates: [String]
        let nonce: String
        let nonce_signature: String
        let encryption_scheme: String
    }
    struct Payload: Decodable {
        let activation_data: String
        let encrypted_pass_data: String
        let ephemeral_public_key: String
    }
    guard endpoint.scheme == "https" else { throw URLError(.badURL) }
    var request = URLRequest(url: endpoint)
    request.httpMethod = "POST"
    request.timeoutInterval = 40
    request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
    request.setValue(requestID.uuidString, forHTTPHeaderField: "Idempotency-Key")
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try JSONEncoder().encode(Challenge(
        certificates: certificates.map { $0.base64EncodedString() },
        nonce: nonce.base64EncodedString(), nonce_signature: nonceSignature.base64EncodedString(),
        encryption_scheme: "ECC_V2"
    ))
    let session = URLSession(configuration: .ephemeral)
    defer { session.finishTasksAndInvalidate() }
    let (data, response) = try await session.data(for: request)
    guard (response as? HTTPURLResponse)?.statusCode == 200 else {
        throw URLError(.badServerResponse)
    }
    let payload = try JSONDecoder().decode(Payload.self, from: data)
    guard let activation = Data(base64Encoded: payload.activation_data), !activation.isEmpty,
          let encrypted = Data(base64Encoded: payload.encrypted_pass_data), !encrypted.isEmpty,
          let ephemeral = Data(base64Encoded: payload.ephemeral_public_key), !ephemeral.isEmpty else {
        throw URLError(.cannotDecodeContentData)
    }
    let result = PKAddPaymentPassRequest()
    result.activationData = activation
    result.encryptedPassData = encrypted
    result.ephemeralPublicKey = ephemeral
    return result
}
