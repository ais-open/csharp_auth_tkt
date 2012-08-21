ModAuthTkt-CSharp
=================

ModAuthTkt Example 
------------------
To create a mod auth tkt with this C# implementation, just follow this example code: 

    var ticketData = new AuthenticationTicketData
    {
	    UserId = "id",
	    UserData = "UserData:this;UserData:this;",
	    TimeStamp = DateTime.Now,
	    IPAddress = "0.0.0.0"
    };
    
    var secret = "9a4e3c23-6566-4076-8e71-901d8b068d47";
    var encode = false;
    
    string modauthtkt = AuthenticationTicket.Create(ticketData, secret, encode);