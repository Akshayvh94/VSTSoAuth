using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace WebApplication3.Controllers
{
    public class HomeController : Controller
    {
        protected static string ClientId = "YOUR_App ID";
        protected static string RedirectUri = "YOUR_APPLICATION_REDIRECT_URL";
        protected static string ClientSecret = "YOUR_Client Secret";

        AccessDetails accessDetails = new AccessDetails();
        /// <summary>
        /// Start page, where user will hit sign in button
        /// </summary>
        /// <returns></returns>
        public ActionResult SignIn()
        {
            return View();
        }
        /// <summary>
        /// Second page where application will be authenticated against Client ID, Client Secret and Redirect URL
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public ActionResult Verify()
        {
            //change this URL scope
            string url = "https://app.vssps.visualstudio.com/oauth2/authorize?client_id={0}&response_type=Assertion&state=User1&scope=vso.identity_manage%20vso.profile_write&redirect_uri={1}";

            string redirectUrl = RedirectUri;// System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];
            string clientId = ClientId;//System.Configuration.ConfigurationManager.AppSettings["ClientId"];
            url = string.Format(url, clientId, redirectUrl);
            return Redirect(url);
        }

        /// <summary>
        /// Call back function, where your app will get Access Token
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public ActionResult Callback(Project model)
        {
            try
            {
                // if the Code from the Request URL is null, [when the User has pressed Deny button], will redirecct to sign in page
                string code1 = Request.QueryString["code"];
                if (code1 == null)
                {
                    return Redirect("../Home/SignIn");
                }
                else
                {
                    string code = Request.QueryString["code"];

                    string redirectUrl = RedirectUri;//System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];
                    string clientId = ClientSecret;//System.Configuration.ConfigurationManager.AppSettings["ClientSecret"];

                    // create the request to Post the Data to get access token
                    string accessRequestBody = GenerateRequestPostData(clientId, code, redirectUrl);

                    //Get Access Token
                    accessDetails = GetAccessToken(accessRequestBody);

                    //Get User profile [ Based on your Scope selection]
                    ProfileDetails Profile = GetProfile(accessDetails);
                    Session["User"] = Profile.displayName;
                    //Get account list associated with logged in user
                    Accounts.AccountList accountList = GetAccounts(Profile.id, accessDetails);

                    model.accessToken = accessDetails.access_token;
                    model.refreshToken = accessDetails.refresh_token;
                    model.accountsForDropdown = new List<string>();

                    if (accountList.count > 0)
                    {
                        foreach (var account in accountList.value)
                        {
                            model.accountsForDropdown.Add(account.accountName);
                        }
                        model.accountsForDropdown.Sort();
                    }

                    return View(model);
                }
            }
            catch (Exception ex)
            {
                return View();
            }
        }
        /// <summary>
        /// Get Account associalted with the logged in user
        /// </summary>
        /// <param name="MemberID"></param>
        /// <param name="Details"></param>
        /// <returns></returns>
        public Accounts.AccountList GetAccounts(string MemberID, AccessDetails Details)
        {
            if (Session["PAT"] != null)
            {
                Details.access_token = Session["PAT"].ToString();
            }
            Accounts.AccountList Accounts = new Accounts.AccountList();
            var client = new HttpClient();
            string requestContent = "https://app.vssps.visualstudio.com/_apis/Accounts?memberId=" + MemberID + "&api-version=3.2-preview";
            var request = new HttpRequestMessage(HttpMethod.Get, requestContent);
            request.Headers.Add("Authorization", "Bearer " + Details.access_token);
            try
            {
                var response = client.SendAsync(request).Result;
                if (response.StatusCode == HttpStatusCode.NonAuthoritativeInformation)
                {
                    Details = Refresh_AccessToken(Details.refresh_token);
                    return GetAccounts(MemberID, Details);
                }
                else if (response.IsSuccessStatusCode)
                {
                    string result = response.Content.ReadAsStringAsync().Result;
                    Accounts = JsonConvert.DeserializeObject<Accounts.AccountList>(result);
                }
                else
                {
                    var errorMessage = response.Content.ReadAsStringAsync();
                    Accounts = null;
                }
            }
            catch (Exception ex)
            {
                return Accounts;
            }
            return Accounts;
        }
        /// <summary>
        /// Creates Request URL
        /// </summary>
        /// <param name="appSecret"></param>
        /// <param name="authCode"></param>
        /// <param name="callbackUrl"></param>
        /// <returns></returns>
        public string GenerateRequestPostData(string appSecret, string authCode, string callbackUrl)
        {
            return String.Format("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={1}&redirect_uri={2}",
                        HttpUtility.UrlEncode(appSecret),
                        HttpUtility.UrlEncode(authCode),
                        callbackUrl
                 );
        }
        /// <summary>
        /// Get Access token
        /// </summary>
        /// <param name="body"></param>
        /// <returns></returns>
        public AccessDetails GetAccessToken(string body)
        {
            var client = new HttpClient();
            client.BaseAddress = new Uri("https://app.vssps.visualstudio.com");

            var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token");

            var requestContent = body;
            request.Content = new StringContent(requestContent, Encoding.UTF8, "application/x-www-form-urlencoded");

            var response = client.SendAsync(request).Result;
            if (response.IsSuccessStatusCode)
            {
                string result = response.Content.ReadAsStringAsync().Result;
                AccessDetails details = Newtonsoft.Json.JsonConvert.DeserializeObject<AccessDetails>(result);
                return details;
            }
            return new AccessDetails();
        }
        /// <summary>
        /// Get User profile
        /// </summary>
        /// <param name="accessDetails"></param>
        /// <returns></returns>
        public ProfileDetails GetProfile(AccessDetails accessDetails)
        {
            ProfileDetails Profile = new ProfileDetails();

            var client = new HttpClient();
            client.BaseAddress = new Uri("https://app.vssps.visualstudio.com");
            var request = new HttpRequestMessage(HttpMethod.Get, "/_apis/profile/profiles/me");

            var requestContent = string.Format(
                "site={0}&api-version={1}", Uri.EscapeDataString("https://app.vssps.visualstudio.com"), Uri.EscapeDataString("1.0"));

            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Add("Authorization", string.Format("Bearer {0}", accessDetails.access_token));
            try
            {
                var response = client.SendAsync(request).Result;
                if (response.StatusCode == HttpStatusCode.NonAuthoritativeInformation)
                {
                    accessDetails = Refresh_AccessToken(accessDetails.refresh_token);
                    GetProfile(accessDetails);
                }
                else if (response.IsSuccessStatusCode)
                {
                    string result = response.Content.ReadAsStringAsync().Result;
                    Profile = JsonConvert.DeserializeObject<ProfileDetails>(result);
                }
                else
                {
                    var errorMessage = response.Content.ReadAsStringAsync();
                    Profile = null;
                }
            }
            catch (Exception ex)
            {
                Profile.ErrorMessage = ex.Message;
            }
            return Profile;
        }
        /// <summary>
        /// Refresh the access token
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public AccessDetails Refresh_AccessToken(string refreshToken)
        {
            using (var client = new HttpClient())
            {
                string redirectUri = RedirectUri;//System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];
                string clientSecret = ClientSecret;// System.Configuration.ConfigurationManager.AppSettings["ClientSecret"];
                var request = new HttpRequestMessage(HttpMethod.Post, "https://app.vssps.visualstudio.com/oauth2/token");
                var requestContent = string.Format(
                    "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}&grant_type=refresh_token&assertion={1}&redirect_uri={2}",
                    HttpUtility.UrlEncode(clientSecret),
                    HttpUtility.UrlEncode(refreshToken), redirectUri
                    );

                request.Content = new StringContent(requestContent, Encoding.UTF8, "application/x-www-form-urlencoded");
                try
                {
                    var response = client.SendAsync(request).Result;
                    if (response.IsSuccessStatusCode)
                    {
                        string result = response.Content.ReadAsStringAsync().Result;
                        AccessDetails accesDetails = JsonConvert.DeserializeObject<AccessDetails>(result);
                        return accesDetails;
                    }
                    else
                    {
                        return null;
                    }
                }
                catch (Exception ex)
                {
                    return null;
                }
            }
        }
        /// <summary>
        /// Model used
        /// </summary>

        public class AccessDetails
        {
            public string access_token { get; set; }
            public string token_type { get; set; }
            public string expires_in { get; set; }
            public string refresh_token { get; set; }
        }
        public class ProfileDetails
        {
            public string displayName { get; set; }
            public string publicAlias { get; set; }
            public string emailAddress { get; set; }
            public int coreRevision { get; set; }
            public DateTime timeStamp { get; set; }
            public string id { get; set; }
            public int revision { get; set; }
            public string ErrorMessage { get; set; }
        }
        public class Project
        {
            public string accessToken { get; set; }
            public string refreshToken { get; set; }
            public List<string> accountsForDropdown { get; set; }
        }
        public class Accounts
        {
            public class Properties
            {
            }
            public class Value
            {
                public string accountId { get; set; }
                public string accountUri { get; set; }
                public string accountName { get; set; }
                public Properties properties { get; set; }
            }

            public class AccountList
            {
                public int count { get; set; }
                public IList<Value> value { get; set; }
            }

        }
    }
}