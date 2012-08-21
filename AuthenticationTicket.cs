/*
 * ModAuthTkt Example 
 * 
 * To create a mod auth tkt with this C# implementation, just follow this example code: 
 * 
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
 * 
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace modauthtkt
{
	/// <summary>
	/// This class is a .NET implementation of mod_auth_tkt 
	/// http://www.openfusion.com.au/labs/mod_auth_tkt/
	/// This is part of the mod_auth_tkt algorithm implementation
	/// </summary>
	public static class AuthenticationTicket
	{
		private const string DefaultSecret = "9a4e3c23-6566-4076-8e71-901d8b068d47";
		private const string CharsToEncode = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:";

		#region Methods

		/// <summary>
		/// Creates a Base64-encoded ticket based on the provided data.
		/// </summary>
		/// <param name="ticketData">Data used to create the ticket.</param>
		/// <param name="secret">Secret key used to create the ticket.</param>
		/// <param name="encode">True if the user id, user data, and tokens are to be encoded; false otherwise</param>
		/// <returns>String ticket</returns>
		/// <remarks>The ticket is created using the mod_auth_tkt algorithm.</remarks>
		public static string Create(AuthenticationTicketData ticketData, string secret, bool encode = false)
		{
			if (ticketData == null)
			{
				return null;
			}

			string digest = CreateDigest(ticketData, secret);
			string userId = (encode) ? Encode(ticketData.UserId, secret, ticketData.UnixTimeStamp, 0) : ticketData.UserId;
			string tokens = (encode)
								? Encode(ticketData.TokensAsString, secret, ticketData.UnixTimeStamp, 4)
								: ticketData.TokensAsString;
			string userData = (encode) ? Encode(ticketData.UserData, secret, ticketData.UnixTimeStamp, 8) : ticketData.UserData;

			string ticket = digest + ticketData.HexTimeStamp + userId + '!';
			ticket += (string.IsNullOrEmpty(tokens)) ? userData : tokens + '!' + userData;

			return Base64Helper.Encode(ticket);
		}

		/// <summary>
		/// Creates a Base64-encoded ticket based on the provided data.
		/// </summary>
		/// <param name="userId">User ID</param>
		/// <param name="userData">User Data</param>
		/// <param name="tokens">Comma-delimited string of data</param>
		/// <param name="timeStamp">Time Stamp</param>
		/// <param name="secret">Secret key used to create the ticket</param>
		/// <param name="encode">True if the user id, user data, and tokens are to be encoded; false otherwise</param>
		/// <param name="ipAddress">IP Address</param>
		/// <param name="version">Version of the mod_auth_tkt algorithm used to create the ticket</param>
		/// <returns>String ticket</returns>
		/// <remarks>The ticket is created using the mod_auth_tkt algorithm.</remarks>
		public static string Create(string userId, string userData, string tokens, DateTime timeStamp, string secret,
									bool encode = false, string ipAddress = AuthenticationTicketData.DefaultIPAddress,
									string version = AuthenticationTicketData.DefaultVersion)
		{
			var ticketData = new AuthenticationTicketData
							 {
								UserId = userId,
								UserData = userData,
								TokensAsString = tokens,
								IPAddress = ipAddress,
								TimeStamp = timeStamp,
								Version = version
							 };

			return Create(ticketData, secret, encode);
		}

		/// <summary>
		/// Validates a ticket based on the provided data.
		/// </summary>
		/// <param name="ticket">Base64-encoded ticket to be validated</param>
		/// <param name="secret">Secret key used to create the ticket</param>
		/// <param name="encoded">True if the user id, user data, and tokens are encoded; false otherwise </param>
		/// <param name="ipAddress">IP Address used to create the ticket</param>
		/// <param name="version">Version of the mod_auth_tkt algorithm used to validate the ticket</param>
		/// <returns>True if ticket is valid, false otherwise</returns>
		public static bool Validate(string ticket, string secret, bool encoded = false,
									string ipAddress = AuthenticationTicketData.DefaultIPAddress,
									string version = AuthenticationTicketData.DefaultVersion)
		{
			AuthenticationTicketData ticketData = ExtractData(ticket, secret, encoded, ipAddress);
			string digest = null;

			if (ticketData != null)
			{
				ticketData.Version = version;
				digest = ticketData.Digest;
			}

			string expectedDigest = CreateDigest(ticketData, secret);

			bool valid = (!string.IsNullOrEmpty(digest) && !string.IsNullOrEmpty(expectedDigest) && expectedDigest == digest);

			return valid;
		}

		/// <summary>
		/// Extracts the data from a provided ticket.
		/// </summary>
		/// <param name="ticket">Base64-encoded ticket to parse for data</param>
		/// <param name="secret">Secret key used to create the ticket</param>
		/// <param name="encoded">True if the user id, user data, and tokens are encoded; false otherwise</param>
		/// <param name="ipAddress">IP Address used to create the ticket</param>
		/// <returns>AuthenticationTicketData instance containing the parsed ticket data.</returns>
		public static AuthenticationTicketData ExtractData(string ticket, string secret = null, bool encoded = false,
														   string ipAddress = AuthenticationTicketData.DefaultIPAddress)
		{
			if (string.IsNullOrWhiteSpace(ticket))
			{
				return null;
			}

			if (string.IsNullOrWhiteSpace(secret))
			{
				secret = DefaultSecret;
			}

			AuthenticationTicketData ticketData = null;
			ticket = Base64Helper.DecodeToString(ticket);

			if (!string.IsNullOrWhiteSpace(ticket) && ticket.Length >= 40)
			{
				ticketData = Parse(ticket);

				if (ticketData != null)
				{
					ticketData.IPAddress = ipAddress;

					if (encoded)
					{
						ticketData.UserId = Decode(ticketData.UserId, secret, ticketData.UnixTimeStamp, 0);
						ticketData.TokensAsString = Decode(ticketData.TokensAsString, secret, ticketData.UnixTimeStamp, 4);
						ticketData.UserData = Decode(ticketData.UserData, secret, ticketData.UnixTimeStamp, 8);
					}
				}
			}

			return ticketData;
		}

		#endregion

		#region Implementation

		/// <summary>
		/// Parses the decoded ticket.
		/// </summary>
		/// <param name="ticket">Ticket to be parsed.</param>
		/// <returns>AuthenticationTicketData instance containing the parsed ticket data.</returns>
		/// <remarks>
		/// The expected format of the ticket is:
		///     digest (32 chars) + hex timestamp (8 chars) + user ID + '!' + user data
		/// OR
		///     digest (32 chars) + hex timestamp (8 chars) + user ID + '!' + tokens + '!' user data
		/// </remarks>
		private static AuthenticationTicketData Parse(string ticket)
		{
			if (string.IsNullOrWhiteSpace(ticket) || ticket.Length < 40)
			{
				return null;
			}

			string[] ticketParts = (ticket.Length > 40) ? ticket.Substring(40).Split('!') : null;
			int length = (ticketParts != null) ? ticketParts.Length : 0;

			if (ticketParts == null) return null;

			var ticketData = new AuthenticationTicketData
							 {
								Digest = ticket.Substring(0, 32),
								HexTimeStamp = ticket.Substring(32, 8),
								UserId = (length > 0) ? ticketParts[0] : string.Empty,
								TokensAsString = (length > 2) ? ticketParts[1] : string.Empty,
								UserData = (length > 1) ? ticketParts[length - 1] : string.Empty
							 };

			return ticketData;
		}

		/// <summary>
		/// Creates the digest portion of the ticket from the provided data.
		/// </summary>
		/// <param name="ticketData">Data used to create the digest</param>
		/// <param name="secret">Secret key used to create the digest</param>
		/// <returns>Digest string</returns>
		/// <remarks>
		/// The algorithm for the digest is as follows:
		/// 	digest = MD5(digest0 + key)
		/// where
		///     Version 1.3: digest0 = MD5(iptstamp + key + user_id + user_data) 
		///     Version 2.0: digest0 = MD5(iptstamp + key + user_id + '\0' + token_list + '\0' + user_data)
		/// </remarks>
		private static string CreateDigest(AuthenticationTicketData ticketData, string secret)
		{
			if (ticketData == null)
			{
				return null;
			}

			if (string.IsNullOrWhiteSpace(secret))
			{
				secret = DefaultSecret;
			}

			string iptStamp = CreateIPTimeStamp(ticketData.IPAddressAsInt, ticketData.UnixTimeStamp);
			string digest;
			const HashHelper.HashType hashType = HashHelper.HashType.MD5;

			switch (ticketData.Version)
			{
				case "1.3":
					digest = HashHelper.Hash(iptStamp + secret + ticketData.UserId + ticketData.UserData, hashType);
					digest = HashHelper.Hash(digest + secret, hashType);
					break;

				case "2.0":
					digest =
						HashHelper.Hash(
							iptStamp + secret + ticketData.UserId + '\0' + ticketData.TokensAsString + '\0' + ticketData.UserData, hashType);
					digest = HashHelper.Hash(digest + secret, hashType);
					break;

				default:
					throw new NotSupportedException(string.Format("Version {0} of the mod_auth_tkt algorithm is not supported",
																  ticketData.Version));
			}

			return digest;
		}

		/// <summary>
		/// Creates the IP Address / Timestamp byte array used in the digest.
		/// </summary>
		/// <param name="ipAddress">IP Address as an unsigned int</param>
		/// <param name="timestamp">Timestamp as an unsigned int</param>
		/// <returns>IPTStamp as a string</returns>
		/// <remarks>
		/// IPTStamp is a 8 bytes long byte array, bytes 0-3 are filled with
		/// client's IP address as a binary number in network byte order, bytes
		/// 4-7 are filled with timestamp as a binary number in network byte
		/// order.
		/// </remarks>
		private static string CreateIPTimeStamp(uint ipAddress, uint timestamp)
		{
			var iptstamp = new byte[8];

			iptstamp[0] = (byte) ((ipAddress & 0xff000000) >> 24);
			iptstamp[1] = (byte) ((ipAddress & 0xff0000) >> 16);
			iptstamp[2] = (byte) ((ipAddress & 0xff00) >> 8);
			iptstamp[3] = (byte) ((ipAddress & 0xff));

			iptstamp[4] = (byte) ((timestamp & 0xff000000) >> 24);
			iptstamp[5] = (byte) ((timestamp & 0xff0000) >> 16);
			iptstamp[6] = (byte) ((timestamp & 0xff00) >> 8);
			iptstamp[7] = (byte) ((timestamp & 0xff));

			return Encoding.GetEncoding("ISO-8859-1").GetString(iptstamp);
		}

		/// <summary>
		/// Encodes a data string.
		/// </summary>
		/// <param name="data">Data to be encoded</param>
		/// <param name="secret">Secret key</param>
		/// <param name="timestamp">Timestamp as an unsigned int</param>
		/// <param name="offset">Offset for local key generation</param>
		/// <returns>Encoded string</returns>
		private static string Encode(string data, string secret, uint timestamp, int offset)
		{
			string md5Key = HashHelper.Hash(timestamp.ToString() + secret, hashType: HashHelper.HashType.MD5);
			int length = CharsToEncode.Length;
			string encoded = string.Empty;

			for (int index = 0; index < data.Length; index++)
			{
				int encodeIndex = CharsToEncode.IndexOf(data[index]);
				if (encodeIndex >= 0)
				{
					int newIndex = (encodeIndex +
									Int32.Parse(md5Key.Substring((offset + index)%md5Key.Length, 1), NumberStyles.AllowHexSpecifier)*7)%
								   length;
					encoded += CharsToEncode[newIndex];
				}
				else
				{
					encoded += data[index];
				}
			}

			return encoded;
		}

		/// <summary>
		/// Decodes a data string.
		/// </summary>
		/// <param name="data">Data to be decoded</param>
		/// <param name="secret">Secret key</param>
		/// <param name="timestamp">Timestamp as an unsigned int</param>
		/// <param name="offset">Offset for local key generation</param>
		/// <returns>Decoded string</returns>
		private static string Decode(string data, string secret, uint timestamp, int offset)
		{
			string md5Key = HashHelper.Hash(timestamp.ToString() + secret, HashHelper.HashType.MD5);
			string decoded = string.Empty;
			int length = CharsToEncode.Length;

			for (int index = 0; index < data.Length; index++)
			{
				int decodeIndex = CharsToEncode.IndexOf(data[index]);
				if (decodeIndex >= 0)
				{
					int newIndex = GetDecodeIndex(
						Int32.Parse(md5Key.Substring((offset + index)%md5Key.Length, 1), NumberStyles.AllowHexSpecifier)*7,
						length,
						decodeIndex);

					decoded += (newIndex < 0) ? '?' : CharsToEncode[newIndex];
				}
				else
				{
					decoded += data[index];
				}
			}

			return decoded;
		}

		/// <summary>
		/// Gets the index in the decoded character string by solving for x in the equation:
		/// 
		/// (x + a) % b = c
		/// 
		/// where x is between 0 and b
		/// </summary>
		/// <param name="a"></param>
		/// <param name="b"></param>
		/// <param name="c"></param>
		/// <returns></returns>
		private static int GetDecodeIndex(int a, int b, int c)
		{
			int x = -1;
			int index = 0;

			while (x < 0)
			{
				x = (b*index++ + c) - a;
			}

			if (x >= b)
			{
				// No solution
				x = -1;
			}

			return x;
		}

		#endregion
	}


	/// <summary>
	/// Data class used in conjunction with AuthenticationTicket
	/// This is part of the mod_auth_tkt algorithm implementation
	/// </summary>
	public class AuthenticationTicketData
	{
		public const string DefaultIPAddress = "0.0.0.0";
		public const string DefaultVersion = "2.0";
		private static DateTime _dateTimeOrigin = new DateTime(1970, 1, 1, 0, 0, 0);

		#region Construction

		/// <summary>
		/// Default constructor
		/// </summary>
		public AuthenticationTicketData()
		{
			_ipAddress = DefaultIPAddress;
			Version = DefaultVersion;
			TimeStamp = _dateTimeOrigin;
		}

		#endregion

		#region Properties

		/// <summary>Gets/sets the version of the mod_auth_tkt algorithm to use</summary>
		public string Version { get; set; }

		/// <summary>Gets/sets the User ID</summary>
		/// <remarks>Must be set for creating an AuthenticationTicket</remarks>
		public string UserId { get; set; }

		/// <summary>Gets/sets the User Data</summary>
		/// <remarks>Optionally set for creating an AuthenticationTicket</remarks>
		public string UserData { get; set; }

		/// <summary>Gets/sets the Tokens</summary>
		/// <remarks>Optionally set for creating an AuthenticationTicket</remarks>
		public List<string> Tokens { get; set; }

		/// <summary>Gets/sets the Time Stamp</summary>
		/// <remarks>Must be set for creating an AuthenticationTicket</remarks>
		public DateTime TimeStamp { get; set; }

		/// <summary>Gets/sets the IP Address</summary>
		/// <remarks>Must be set for creating an AuthenticationTicket. Set to "0.0.0.0" by default.</remarks>
		public string IPAddress
		{
			get { return _ipAddress; }
			set
			{
				if (IPAddressHelper.IsValid(value))
				{
					_ipAddress = value;
				}
			}
		}

		/// <summary>Gets/sets the Digest</summary>
		/// <remarks>Set upon parsing. Does not need to be set by the user.</remarks>
		public string Digest { get; set; }

		/// <summary>Gets the tokens in a comma-delimited string or sets the token list from a comma-delimited string.</summary>
		public string TokensAsString
		{
			get { return (Tokens != null && Tokens.Count > 0) ? string.Join(",", Tokens.ToArray()) : string.Empty; }
			set
			{
				if (!string.IsNullOrEmpty(value))
				{
					string[] tokens = value.Split(',');
					Tokens = new List<string>(tokens);
				}
			}
		}

		/// <summary>Gets the IP Address as an unsigned int</summary>
		public uint IPAddressAsInt
		{
			get
			{
				uint convertedIP = 0;

				byte[] ipBytes = IPAddressHelper.StringToIPAddressBytes(IPAddress);

				if (ipBytes != null)
				{
					convertedIP = (uint) (ipBytes[0] << 24)
								  + (uint) (ipBytes[1] << 16)
								  + (uint) (ipBytes[2] << 8)
								  + (ipBytes[3]);
				}

				return convertedIP;
			}
		}

		/// <summary>Gets/sets the time stamp as an unsigned int.</summary>
		public uint UnixTimeStamp
		{
			get { return Convert.ToUInt32((TimeStamp - _dateTimeOrigin).TotalSeconds); }
			set { TimeStamp = _dateTimeOrigin.AddSeconds(value); }
		}

		/// <summary>Gets/sets the time stamp as a hex string.</summary>
		public string HexTimeStamp
		{
			get { return UnixTimeStamp.ToString("x8"); }
			set
			{
				if (!string.IsNullOrEmpty(value))
				{
					uint timeStamp;
					if (uint.TryParse(value, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out timeStamp))
					{
						UnixTimeStamp = timeStamp;
					}
				}
			}
		}

		#endregion

		private string _ipAddress;
	}


	internal static class IPAddressHelper
	{
		/// <summary>
		/// Converts a string to an IPAddress object
		/// </summary>
		/// <param name="ipAddress">IP address as a string</param>
		/// <returns>IPAddress object</returns>
		static IPAddress StringToIPAddress(string ipAddress)
		{
			IPAddress ip = null;

			if (!string.IsNullOrWhiteSpace(ipAddress))
			{
				IPAddress.TryParse(ipAddress, out ip);
			}

			return ip;
		}

		/// <summary>
		/// Converts a string to a byte array representation of an IP address
		/// </summary>
		/// <param name="ipAddress">IP address as a string</param>
		/// <returns>Byte array</returns>
		public static byte[] StringToIPAddressBytes(string ipAddress)
		{
			byte[] ipBytes = null;
			IPAddress ip = StringToIPAddress(ipAddress);

			if (ip != null)
			{
				ipBytes = ip.GetAddressBytes();
			}

			return ipBytes;
		}

		/// <summary>
		/// Determines if a string is a valid IP address
		/// </summary>
		/// <param name="ipAddress">IP address as a string</param>
		/// <returns>True if valid, false otherwise</returns>
		public static bool IsValid(string ipAddress)
		{
			IPAddress ip = StringToIPAddress(ipAddress);

			return (ip != null);
		}
	}

	internal static class Base64Helper
	{
		/// <summary>
		/// Encodes a string using Base64.
		/// </summary>
		/// <param name="data">Data string to encode.</param>
		/// <returns>Base64-encoded string.</returns>
		public static string Encode(string data)
		{
			byte[] bytesToEncode = string.IsNullOrEmpty(data) ? null : Encoding.UTF8.GetBytes(data);
			return Encode(bytesToEncode);
		}

		/// <summary>
		/// Encodes a byte array using Base64.
		/// </summary>
		/// <param name="data">Byte array to encode.</param>
		/// <returns>Base64-encoded string.</returns>
		static string Encode(byte[] data)
		{
			return (data == null) ? null : Convert.ToBase64String(data);
		}

		/// <summary>
		/// Decodes data to a string using Base64.
		/// </summary>
		/// <param name="data">Data string to decode.</param>
		/// <returns>Base64-decoded string.</returns>
		public static string DecodeToString(string data)
		{
			byte[] decodedBytes = DecodeToBytes(data);
			return (decodedBytes == null) ? null : Encoding.UTF8.GetString(decodedBytes);
		}

		/// <summary>
		/// Decodes data to a byte array using Base64.
		/// </summary>
		/// <param name="data">Data string to decode</param>
		/// <returns>Base64-decoded byte array.</returns>
		static byte[] DecodeToBytes(string data)
		{
			byte[] decodedBytes;

			try
			{
				decodedBytes = (string.IsNullOrWhiteSpace(data)) ? null : Convert.FromBase64String(data);
			}
			catch
			{
				return null;
			}

			return decodedBytes;
		}
	}

	internal static class HashHelper
	{
		#region HashType enum

		/// <summary>
		/// Hash methodologies
		/// </summary>
		public enum HashType
		{
			MD5,
			SHA1,
			SHA256,
			SHA512
		}

		#endregion

		private const string DefaultEncoding = "ISO-8859-1";

		/// <summary>
		/// Creates a hash string using the specified hash methodology.
		/// </summary>
		/// <param name="text">String to be hashed</param>
		/// <param name="hashType">Type of hashing to perform</param>
		/// <param name="encoder">(Optional) Character encoding for converting the text string to bytes</param>
		/// <returns>Hashed string</returns>
		/// <remarks>Default encoding is ISO-8859-1</remarks>
		public static string Hash(string text, HashType hashType, Encoding encoder = null)
		{
			HashAlgorithm hasher = null;

			switch (hashType)
			{
				case HashType.MD5:
					hasher = MD5.Create();
					break;

				case HashType.SHA1:
					hasher = SHA1.Create();
					break;

				case HashType.SHA256:
					hasher = SHA256.Create();
					break;

				case HashType.SHA512:
					hasher = SHA512.Create();
					break;
			}

			return Hash(text, hasher, encoder);
		}

		/// <summary>
		/// Creates a hash string using the specified hash methodology.
		/// </summary>
		/// <param name="text">String to be hashed</param>
		/// <param name="hasher">Hash algorithm with which to perform the hash</param>
		/// <param name="encoder">(Optional) Character encoding for converting the text string to bytes</param>
		/// <returns>Hashed string</returns>
		/// <remarks>Default encoding is ISO-8859-1</remarks>
		public static string Hash(string text, HashAlgorithm hasher, Encoding encoder = null)
		{
			string hash = string.Empty;

			if (!string.IsNullOrEmpty(text) && hasher != null)
			{
				if (encoder == null)
				{
					encoder = Encoding.GetEncoding(DefaultEncoding);
				}

				byte[] hashBytes = hasher.ComputeHash(encoder.GetBytes(text));
				hash = BytesToString(hashBytes);
			}

			return hash;
		}

		private static string BytesToString(IEnumerable<byte> bytes)
		{
			var sb = new StringBuilder();

			foreach (byte b in bytes)
			{
				sb.Append(b.ToString("x2"));
			}

			return sb.ToString();
		}
	}
}