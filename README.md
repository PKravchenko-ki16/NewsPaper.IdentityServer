# NewsPaper.IdentityServer
 
This is IdentityServer4 with authentication and authorization on ASP.NET Core 3.1 with OAuth2 & OpenID Connect. Authentication based on Claims, Policy, Refresh token and Access token and Identity Token.

## Authentication process

When a user contacts a client, he redirects the user to the Open ID Connect Provider, which asks the user for a login and password. If successful, it returns an identity token and an access token, with which the user can access the protected resource.
![Alt-текст](https://hsto.org/getpro/habr/post_images/c13/afc/ee5/c13afcee5226ddb135df9836d3321b17.png "Authentication process")

## Links to project repositories
- :white_check_mark:[NewsPaper.MassTransit.Configuration](https://github.com/PKravchenko-ki16/NewsPaper.MassTransit.Configuration)
- :white_check_mark:[NewsPaper.MassTransit.Contracts](https://github.com/PKravchenko-ki16/NewsPaper.MassTransit.Contracts)
- :white_check_mark:NewsPaper.IdentityServer
- :white_check_mark:[Newspaper.GateWay](https://github.com/PKravchenko-ki16/Newspaper.GateWay)
- :white_check_mark:[NewsPaper.Accounts](https://github.com/PKravchenko-ki16/NewsPaper.Accounts)
- :white_check_mark:[NewsPaper.Articles](https://github.com/PKravchenko-ki16/NewsPaper.Articles)
- :white_check_mark:[NewsPaper.GatewayClientApi](https://github.com/PKravchenko-ki16/NewsPaper.GatewayClientApi)
- :white_check_mark:[NewsPaper.Client.Mvc](https://github.com/PKravchenko-ki16/NewsPaper.Client.Mvc)
