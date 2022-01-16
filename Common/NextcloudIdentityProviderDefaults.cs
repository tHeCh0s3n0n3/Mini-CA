using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Common
{
    public static class NextcloudIdentityProviderDefaults
    {
        public const string SchemeName = "Nextcloud";

        public const string AuthorizationEndpointPath = "/index.php/apps/oauth2/authorize";

        public const string TokenEndpointPath = "/index.php/apps/oauth2/api/v1/token";

        public const string UserInformationEndpointPath = "/ocs/v1.php/cloud/users/";
    }
}
