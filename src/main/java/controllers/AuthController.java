package controllers;

import com.scalekit.ScalekitClient;
import com.scalekit.internal.http.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    ScalekitClient scalekit;

    @Value("${auth.redirect.url}")
    private String redirectUrl;

    @Value("${auth.host.url}")
    private String host;

    @Value("${auth.ui.url}")
    private String uiUrl;

    private final  UserStore userStore = new UserStore();


    @PostMapping( path = "/login")
    public ResponseEntity<Map<String, String>> loginHandler(@RequestBody LoginRequest body) {
        AuthorizationUrlOptions options = new AuthorizationUrlOptions();
        if (body.getConnectionId() != null) {
            options.setConnectionId(body.getConnectionId());
        }
        if (body.getOrganizationId() != null) {
            options.setOrganizationId(body.getOrganizationId());
        }
        if (body.getEmail() != null) {
            options.setLoginHint(body.getEmail());
        }
        try {
            String url = scalekit.authentication().getAuthorizationUrl(redirectUrl, options).toString();
            System.out.println(url);
            return ResponseEntity.ok(Collections.singletonMap("url", url));
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.singletonMap("error", e.getMessage()));
        }
    }

    @GetMapping("/callback")
    public RedirectView callbackHandler(@RequestParam(required = false) String code,
                                        @RequestParam(required = false, name = "error_description") String errorDescription,
                                        @RequestParam(required = false, name = "idp_initiated_login") String idpInitiatedLoginToken,

                                        HttpServletResponse response) throws IOException {
        if (errorDescription != null) {
            response.sendError(HttpStatus.BAD_REQUEST.value(), errorDescription);
            return null;
        }
        if (idpInitiatedLoginToken != null) {
            IdpInitiatedLoginClaims idpInitiatedLoginClaims = scalekit
                    .authentication()
                    .getIdpInitiatedLoginClaims(idpInitiatedLoginToken);
            if (idpInitiatedLoginClaims == null) {
                response.sendError(HttpStatus.BAD_REQUEST.value(), "Invalid idp_initiated_login token");
                return null;
            }

            AuthorizationUrlOptions options = new AuthorizationUrlOptions();
            if (idpInitiatedLoginClaims.getConnectionID() != null) {
                options.setConnectionId(idpInitiatedLoginClaims.getConnectionID());
            }
            if (idpInitiatedLoginClaims.getOrganizationID() != null) {
                options.setOrganizationId(idpInitiatedLoginClaims.getOrganizationID());
            }
            if (idpInitiatedLoginClaims.getLoginHint() != null) {
                options.setLoginHint(idpInitiatedLoginClaims.getLoginHint());
            }
            String url = scalekit.authentication().getAuthorizationUrl(redirectUrl, options).toString();
            response.sendRedirect(url);
            return null;
        }
        if (code == null || code.isEmpty()) {
            response.sendError(HttpStatus.BAD_REQUEST.value(), "code not found");
            return null;
        }
        try {
            AuthenticationResponse res = scalekit.authentication().authenticateWithCode(code, redirectUrl, new AuthenticationOptions());
            String[] uidParts = res.getIdTokenClaims().getId().split(";");
            String uid = uidParts[uidParts.length - 1];
            userStore.addUser(uid, res.getIdTokenClaims());

            Cookie cookie = new Cookie("uid", uid);
            cookie.setPath("/");
            cookie.setHttpOnly(false);
            cookie.setMaxAge(60 * 60 * 24 * 365);
            cookie.setSecure(false);
            response.addCookie(cookie);

            System.out.println("Redirecting to profile");
            return new RedirectView(uiUrl);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), e.getMessage());
            return null;
        }
    }

    @GetMapping("/me")
    public ResponseEntity<IdTokenClaims> meHandler(@CookieValue(name = "uid", required = false) String uid) {
        if (uid == null || uid.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        IdTokenClaims user = userStore.getUser(uid);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return ResponseEntity.ok(user);
    }

    @PostMapping("/logout")
    public RedirectView logoutHandler(HttpServletResponse response) {
        Cookie cookie = new Cookie("uid", "");
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return new RedirectView(uiUrl);
    }
}
