1. Run `mvn release:prepare` to tag the release and update the pom
2. Run `mvn release:perform -Prelease` to push to Maven Central
3. Update `README.md` to indicate the latest released version