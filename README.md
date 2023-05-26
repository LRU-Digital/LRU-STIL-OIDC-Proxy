# OIDC Proxy for STIL SSO Proxy

STIL (Styrelsen for læring og IT) has decided to retire the STIL SSOProxy and will in the future only support two authentication protocols: SAML and OIDC.

A lot of the Danish EdTech community uses SSOProxy, the sunsetting of the SSOProxy will mean that they have to make changes to their applications.

Some of the companies in the Danish EdTech community are smaller companies, that do not have large R&D budgets, and there is a risk that the migration to a new and more complex protocol will force them to reconsider their product. 

Lindhardt&Ringhof has therefore decided to implement an OIDC proxy and make it open-source to support the EdTech community. This will work as a proxy between the retired SSOProxy protocol and the new OIDC protocol. This means that you will only need:

* Exchange OIDC metadata with STIL
* Clone this project, configure it and deploy it to a server
* Change the url for the SSOProxy in your current project

## Development

### Storing secrets in user-secrets

To prevent storing your secrets in appsettings.json consider using dotnet user secrets during development

dotnet user-secrets init
dotnet user-secrets set "STILOIDC:ClientId" "{your-client-id}"
dotnet user-secrets set "STILOIDC:ClientSecret" "{your-client-secret}"

## Configuration

The Stil SSOProxy uses a shared clientid and a shared secret for authenticating the requests and responses in the protocol.
This proxy can respond using multiple clientid/secret combination. The clientid and secret is configured in the custom configuration section

```json
"SSOProxyClients": [
    {
      "ClientId": "test",
      "Secret": "abc123"
    },
    {
      "ClientId": "test2",
      "Secret": "abc123"
    }
  ]
```

The Open-id-connect protocol uses parameters for the protocol. These are defined in the configuration below

```json
"STILOIDC": {
    "Domain": "et-broker.unilogin.dk/auth/realms/broker",
    "ClientId": "{your-client-id}",
    "ClientSecret": "{your-client-secret}",
    "UserNameClaimType": "dk:unilogin:uniid"
  }
```

The UserNameClaimType defines where the typename of the claim containing uniid.

## More information

### STIL information

https://et-broker.unilogin.dk/auth/realms/broker/.well-known/openid-configuration

https://viden.stil.dk/display/OFFSKOLELOGIN/SSOproxy+HTTP#SSOproxyHTTP-Hvordanvirkerdet?

### OpenIdConnect and .Net core

https://andrewlock.net/an-introduction-to-openid-connect-in-asp-net-core/

https://github.com/onelogin/openid-connect-dotnet-core-sample

https://docs.criipto.com/verify/integrations/aspnet-core-v6/


### OpenIdConnect

https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

https://openid.net/specs/openid-connect-rpinitiated-1_0.html


### OpenIdConnect and Google

https://developers.google.com/identity/protocols/oauth2/openid-connect

### OIO and OpenIdConnect

https://digst.dk/media/24669/oio-oidc-profiles-v091.pdf