using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Windows.Security.Authentication.Web.Core;
using Windows.Security.Credentials;

namespace CredentialManipulater
{
    public class CredentialManipulater
    {
        private static string LENOVO_PROVIDER_ID = "https://www.passport.lenovo.com";
        private static string LENOVO_SCOPE = "scope";
        private static string LENOVO_CLIENT_ID = "clientid";

        public static string StarterToken = "ZAgAAAAAAA_STARTER_1.0_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        private WebAccountProvider _webAccountProvider;
        public string ActiveUserToken { get; private set; }
        public string ActiveUserLenovoIdEmailAddress { get; private set; }
        public LenovoIdStatus CurrentStatus { get; private set; }

        private bool firstTimeUserInteractionRequired = true;

        public async Task<WebAccountProvider> GetLenovoIdAccountProvider()
        {
            // Only get new provider if it's null
            if (_webAccountProvider == null)
            {
                try
                {
                    WebAccountProvider provider = null;
                    provider = await WebAuthenticationCoreManager.FindAccountProviderAsync(LENOVO_PROVIDER_ID);

                    if (null != provider)
                    {
                        _webAccountProvider = provider;
                    }
                    else
                    {
                        //try again
                        provider = await WebAuthenticationCoreManager.FindAccountProviderAsync(LENOVO_PROVIDER_ID);
                        if (null != provider)
                        {
                            _webAccountProvider = provider;
                        }
                        else
                        {
                            //Logger.Log(LogSeverity.Error, "LenovoIdAgent: Provider not found");
                        }
                    }
                }
                catch (Exception ex)
                {
                    //Logger.Log(LogSeverity.Exception, "LenovoIdAgent: Provider retrieval threw exception", ex);
                }
            }

            return _webAccountProvider;
        }

        public async Task<string> GetToken(WebAccountProvider provider, string scope, string clientId)
        {
            string result = string.Empty;
            if (null != provider)
            {
                try
                {
                    // The LenovoID team said we should avoid passing emtpy strings as parameters as per Microsoft's API documentation
                    if (String.IsNullOrEmpty(scope)) scope = "scope";
                    if (String.IsNullOrEmpty(clientId)) clientId = "clientid";

                    WebTokenRequest webTokenRequest = new WebTokenRequest(provider, scope, clientId);
                    WebTokenRequestResult webTokenRequestResult = await WebAuthenticationCoreManager.GetTokenSilentlyAsync(webTokenRequest);

                    if (webTokenRequestResult != null && webTokenRequestResult.ResponseStatus == WebTokenRequestStatus.Success)
                    {
                        if (webTokenRequestResult.ResponseData != null && webTokenRequestResult.ResponseData.Count > 0 && webTokenRequestResult.ResponseData[0].Token != null)
                        {
                            //formats userid|token
                            result = webTokenRequestResult.ResponseData[0].Token;
                        }
                    }
                    //Logger.Log(LogSeverity.Information, "Token received", result.ToString());
                }
                catch (Exception ex)
                {
                    //Logger.Log(LogSeverity.Information, "Lenovo ID App is not installed.", ex);
                }
            }
            else
            {
                //Logger.Log(LogSeverity.Information, "LenovoIdAgent: GetTokenSilentlyAsync - provider was null");
            }

            return result;
        }

        public void SetCurrentStatusByToken(string token)
        {
            if (!string.IsNullOrEmpty(token))
            {
                int index = token.IndexOf('|');
                if (index >= 0)
                {
                    // Token found, save the info
                    ActiveUserToken = token.Substring(index + 1);
                    ActiveUserLenovoIdEmailAddress = token.Substring(0, index);
                    if (ActiveUserLenovoIdEmailAddress.EndsWith("@lenovoid.com") && ActiveUserToken.Equals(LenovoIdConstants.StarterToken))
                    {
                        CurrentStatus = LenovoIdStatus.StarterId;
                    }
                    else
                    {
                        CurrentStatus = LenovoIdStatus.SignedIn;
                    }
                }
                else
                {
                    // No token, user is signing out
                    CurrentStatus = LenovoIdStatus.SignedOut;
                }
            }
        }

        private async Task<bool> GetTokenSilentlyAsync(WebAccountProvider provider, String scope, String clientId)
        {
            bool result = false;
            if (null != provider)
            {
                try
                {
                    // The LenovoID team said we should avoid passing emtpy strings as parameters as per Microsoft's API documentation
                    if (String.IsNullOrEmpty(scope)) scope = "scope";
                    if (String.IsNullOrEmpty(clientId)) clientId = "clientid";

                    WebTokenRequest webTokenRequest = new WebTokenRequest(provider, scope, clientId);
                    WebTokenRequestResult webTokenRequestResult = await WebAuthenticationCoreManager.GetTokenSilentlyAsync(webTokenRequest);
                    result = await ParseTokenResultAsync(webTokenRequestResult, false);
                    //Logger.Log(LogSeverity.Information, "Token received", result.ToString());
                }
                catch (Exception ex)
                {
                    //Logger.Log(LogSeverity.Information, "Lenovo ID App is not installed.", ex);
                    result = false;
                }
            }
            else
            {
                //await SetLIDProfileCache();
                //Logger.Log(LogSeverity.Information, "LenovoIdAgent: GetTokenSilentlyAsync - provider was null");
            }
            return result;
        }

        private async Task<bool> ParseTokenResultAsync(WebTokenRequestResult result, bool allowDownloadSiteToPopUp)
        {
            bool success = false;
            if (result != null)
            {
                if (result.ResponseStatus == WebTokenRequestStatus.Success)
                {
                    if (result.ResponseData != null && result.ResponseData.Count > 0 && result.ResponseData[0].Token != null)
                    {
                        string value = result.ResponseData[0].Token;
                        int index = value.IndexOf('|');
                        // Format is userID|token
                        if (index >= 0)
                        {
                            // Token found, save the info
                            ActiveUserToken = value.Substring(index + 1);
                            ActiveUserLenovoIdEmailAddress = value.Substring(0, index);
                            if (ActiveUserLenovoIdEmailAddress.EndsWith("@lenovoid.com") && ActiveUserToken.Equals(LenovoIdConstants.StarterToken))
                            {
                                CurrentStatus = LenovoIdStatus.StarterId;
                            }
                            else
                            {
                                CurrentStatus = LenovoIdStatus.SignedIn;
                            }
                        }
                        else
                        {
                            // No token, user is signing out
                            CurrentStatus = LenovoIdStatus.SignedOut;
                        }

                        success = true;
                    }
                    else
                    {
                        //Logger.Log(LogSeverity.Error, "LenovoIdAgent: Couldn't parse response because response data wasn't complete");
                    }
                }
                else if (result.ResponseStatus == WebTokenRequestStatus.UserCancel)
                {
                    // User cancelled out of the Lenovo ID sign in interface
                    //Logger.Log(LogSeverity.Error, "LenovoIdAgent: User cancelled login prompt");
                }
                else if (result.ResponseStatus == WebTokenRequestStatus.UserInteractionRequired)
                {
                    /*Start -- Temporary code to accomodate the new LID app as it is not backward compatible*/
                    if (firstTimeUserInteractionRequired)
                    {
                        firstTimeUserInteractionRequired = false;
                        var provider = await GetLenovoIdAccountProvider();
                        var status = await GetTokenSilentlyAsync(provider, LenovoIdConstants.PROVIDER_SCOPE_SILENTLY_V2, LENOVO_CLIENT_ID);
                        if (status)
                        {
                            firstTimeUserInteractionRequired = true;
                            return status;
                        }
                    }
                    /*End -- Temporary code*/

                    // User interaction is required to complete the request. This option is only applicable to requests made with GetTokenSilentlyAsync.
                    // If this status is returned, repeat the request with RequestTokenAsync.
                    CurrentStatus = LenovoIdStatus.SignedOut;

                    //Logger.Log(LogSeverity.Information, "ResponseStatus is UserInteractionRequired");
                }
                else
                {
                    // Status is AccountProviderNotAvailable, ProviderError, or AccountSwitch
                    CurrentStatus = LenovoIdStatus.SignedOut;
                    ActiveUserLenovoIdEmailAddress = string.Empty;
                    string errorMessage = string.Empty;

                    if (result.ResponseError != null && !String.IsNullOrWhiteSpace(result.ResponseError.ErrorMessage))
                    {
                        errorMessage = " - Error message: " + result.ResponseError.ErrorCode + " " + result.ResponseError.ErrorMessage;
                    }

                    // Launch the download site if appropriate
                    if (allowDownloadSiteToPopUp)
                    {
                        //Logger.Log(LogSeverity.Error, "LenovoIdAgent: ResponseStatus was " + result.ResponseStatus + " and the download site will launch" + errorMessage);
                    }
                    else
                    {
                        //Logger.Log(LogSeverity.Error, "LenovoIdAgent: ResponseStatus was " + result.ResponseStatus + " and the download site was NOT launched" + errorMessage);
                    }
                }
            }
            else
            {
                //Logger.Log(LogSeverity.Error, "LenovoIdAgent: WebTokenRequestResult was null, can't parse it");
            }

            return success;
        }
    }

    public enum LenovoIdStatus
    {
        Unknown,
        StarterId,
        SignedIn,
        SignedOut,
        Disabled,
    }

    internal static class LenovoIdConstants
    {
        public static Guid FeatureId = new Guid("E0DF659E-02A6-417C-8B39-DB116529BFDD");
        public static string RETURN_RESULT = "EErrorType";
        public static string RETURN_TGT = "TGT";
        public static string RETURN_UST = "UST";
        public static string RETURN_ST = "ST";
        public static string CLIENT_ID_COMPANION = "A91C73A7-6A57-463C-8377-12A203CAB981";
        public static string CLIENT_ID_SETTINGS = "F1C57DF8-51B2-4EFC-999C-81F219C2630A";
        public const string PROVIDER_SCOPE_SILENTLY_V2 = "LID_PROVIDER_SILENTLY_V2";
        public static string PROVIDER_SCOPE_INTERACTION_V2 = "LID_PROVIDER_INTERACTION_V2";
        public const string PROVIDER_SCOPE_SILENTLY_V3 = "LID_PROVIDER_SILENTLY_V3";
        public static string PROVIDER_SCOPE_INTERACTION_V3 = "LID_PROVIDER_INTERACTION_V3";
        public static string StarterToken = "ZAgAAAAAAA_STARTER_1.0_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        public static string Format = "Format=";
    }
}
