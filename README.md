## WSO2 IS - Password Policy - Minimum Password Age Enforcer

### How to start

- Build this component using `mvn clean install`
- Deploy the jar in IS_HOME/repository/components/dropins
- Add the following configurations in the IS_HOME/repository/conf/identity/identity-event.properties

```
module.name.13=passwordMinAge
passwordMinAge.subscription.1=PRE_UPDATE_CREDENTIAL
passwordMinAge.subscription.2=PRE_UPDATE_CREDENTIAL_BY_ADMIN
passwordMinAge.enable=false
passwordMinAge.count=5
```
- Restart the IS server
- In the Resident Identity Provider configuration -> Password Policies, enable both `Password History` and `Password Minimum Age` 
