# CircleCI Integration

Add to your `.circleci/config.yml`:

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: armur/agent:latest
    steps:
      - checkout
      - run:
          name: Armur Security Scan
          command: armur scan . --fail-on-severity high --format sarif --output results.sarif
      - store_artifacts:
          path: results.sarif

workflows:
  security:
    jobs:
      - security-scan
```
