// @flow
import passport from "@outlinewiki/koa-passport";
import Router from "koa-router";
import { Strategy as OidcStrategy, Issuer, generators } from "openid-connect";
import accountProvisioner from "../../commands/accountProvisioner";
import env from "../../env";
import {
} from "../../errors";
import passportMiddleware from "../../middlewares/passport";
import { getAllowedDomains } from "../../utils/authentication";
import { StateStore } from "../../utils/passport";

const router = new Router();
const providerName = "oidc";
const OIDC_CLIENT_ID = process.env.OIDC_CLIENT_ID;
const OIDC_CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET;
const OIDC_DISCOVERY_DOCUMENT = process.env.OIDC_DISCOVERY_DOCUMENT;
const allowedDomains = getAllowedDomains();

const scopes = [];

export const config = {
  name: "OpenID Connect",
  enabled: !!OIDC_CLIENT_ID,
};

if (OIDC_CLIENT_ID) {
  ;(async () => {
    const issuer = await Issuer.discover(OIDC_DISCOVERY_DOCUMENT);
    const client = new issuer.Client();

    passport.use(new OidcStrategy({
      client: client, 
      params: {
        client_id: OIDC_CLIENT_ID,
        client_secret: OIDC_CLIENT_SECRET,
        redirect_uri: `${env.URL}/auth/oidc.callback`,
        scope: scopes,
      },
      passReqToCallback: true,
    },
    async function (tokenSet, userInfo, done){
      log(tokenSet, userInfo);
      try {
        const domain = profile._json.hd;

        // if (!domain) {
        //   throw new GoogleWorkspaceRequiredError();
        // }

        // if (allowedDomains.length && !allowedDomains.includes(domain)) {
        //   throw new GoogleWorkspaceInvalidError();
        // }

        const subdomain = domain.split(".")[0];
        const teamName = capitalize(subdomain);

        const result = await accountProvisioner({
          ip: req.ip,
          team: {
            name: teamName,
            domain,
            subdomain,
          },
          user: {
            name: profile.displayName,
            email: profile.email,
            avatarUrl: profile.picture,
          },
          authenticationProvider: {
            name: providerName,
            providerId: domain,
          },
          authentication: {
            providerId: profile.id,
            accessToken,
            refreshToken,
            scopes,
          },
        });
        return done(null, result.user, result);
      } catch (err) {
        return done(err, null);
      }
    }))
  })()

  router.get("oidc", passport.authenticate(providerName));

  router.get("oidc.callback", passportMiddleware(providerName));
}

export default router;
