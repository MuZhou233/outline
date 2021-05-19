// @flow
import passport from "@outlinewiki/koa-passport";
import Router from "koa-router";
import { capitalize } from "lodash";
import { Strategy as KeyCloakStrategy } from "passport-keycloak-oauth2-oidc";
import accountProvisioner from "../../commands/accountProvisioner";
import env from "../../env";
import passportMiddleware from "../../middlewares/passport";
import { getAllowedDomains } from "../../utils/authentication";
import { StateStore } from "../../utils/passport";

const router = new Router();
const providerName = "keycloak";
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID;
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET;
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM;
const KEYCLOAK_CLIENT_PUBLIC = process.env.KEYCLOAK_CLIENT_PUBLIC;
const KEYCLOAK_SSL_REQUIRED = process.env.KEYCLOAK_SSL_REQUIRED;
const KEYCLOAK_AUTH_URL = process.env.KEYCLOAK_AUTH_URL;

const allowedDomains = getAllowedDomains();

const scopes = [];

export const config = {
  name: "KeyCloak",
  enabled: !!KEYCLOAK_CLIENT_ID,
};

if (KEYCLOAK_CLIENT_ID) {
  passport.use(
    new KeyCloakStrategy(
      {
        clientID: KEYCLOAK_CLIENT_ID,
        clientSecret: KEYCLOAK_CLIENT_SECRET,
        realm: KEYCLOAK_REALM,
        publicClient: KEYCLOAK_CLIENT_PUBLIC,
        sslRequired: KEYCLOAK_SSL_REQUIRED,
        authServerURL: KEYCLOAK_AUTH_URL,
        callbackURL: `${env.URL}/auth/keycloak.callback`,
      },
      async function (req, accessToken, refreshToken, profile, done) {
        try {
          const result = await accountProvisioner({
            ip: req.ip,
            team: {
              name: KEYCLOAK_REALM,
              subdomain: "",
              avatarUrl: "",
            },
            user: {
              name: profile.username,
              email: profile.email,
              avatarUrl: "",
            },
            authenticationProvider: {
              name: providerName,
              providerId: KEYCLOAK_REALM,
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
      }
    )
  );

  router.get("keycloak", passport.authenticate(providerName));

  router.get("keycloak.callback", passportMiddleware(providerName));
}

export default router;
