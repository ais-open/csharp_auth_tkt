ModAuthTkt-CSharp
=================

Introduction
-------------
For an introduction to ModAuthTkt-CSharp, see [Single Sign-On Using Mod_Auth_Tkt](http://blog.appliedis.com/2012/09/10/single-sign-on-using-mod_auth_tkt/)


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
    
Credits
--------
This code was ported to C# by [Robin Kaye](http://www.linkedin.com/pub/robin-kaye/1/72/439 "Robin Kaye on LinkedIn") of [Applied Information Sciences](http://appliedis.com "AIS") (AIS).  
It has since been maintained and tweaked by David Benson.

