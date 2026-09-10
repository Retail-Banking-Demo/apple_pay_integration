# Intentional Sonar findings

`app/sonar_issues_demo.py` contains deliberately defective code for demonstrating
Sonar findings and fixes. It is not imported by the service and exposes no routes.
Do not connect these functions to the issuer integration. The password is fictional.

| Category | Example | Expected rule |
| --- | --- | --- |
| Security | Disabled TLS certificate verification | [S4830](https://rules.sonarsource.com/python/RSPEC-4830/) |
| Security | Disabled TLS hostname verification | [S5527](https://rules.sonarsource.com/python/RSPEC-5527/) |
| Security hotspot | Hardcoded operator password | [S2068](https://rules.sonarsource.com/python/RSPEC-2068/) |
| Reliability | Return from `finally` hides failures | [S1143](https://rules.sonarsource.com/python/RSPEC-1143/) |
| Reliability | Repeated branch condition | [S1862](https://rules.sonarsource.com/python/RSPEC-1862/) |
| Maintainability | Unused `audit_label` local | [S1481](https://rules.sonarsource.com/python/RSPEC-1481/) |
| Maintainability | Generic `Exception` | [S112](https://rules.sonarsource.com/python/RSPEC-112/) |
| Maintainability | Empty exception handler | [S108](https://rules.sonarsource.com/python/RSPEC-108/) |

The current `sonar.sources=.` includes this module. Run your normal Sonar scan
from this repository. Results depend on the installed analyzer and active Python
quality profile; enable the listed rules if needed. Hotspots appear separately
from security vulnerabilities. Exact issue totals and severity are not guaranteed.
No Sonar scan has been executed as part of adding this fixture.
