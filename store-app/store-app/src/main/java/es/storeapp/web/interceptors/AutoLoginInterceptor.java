package es.storeapp.web.interceptors;

import es.storeapp.business.entities.User;
import es.storeapp.business.services.UserService;
import es.storeapp.common.Constants;
import es.storeapp.web.cookies.UserInfo;
import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.servlet.HandlerInterceptor;

//se añaden
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AutoLoginInterceptor implements HandlerInterceptor {

    private final UserService userService;

    // verificar la autenticidad del token, si es valido -> claims
    private final String secretKey = System.getenv("JWT_SECRET_KEY");
    private static final Logger logger = LoggerFactory.getLogger(AutoLoginInterceptor.class);

    public AutoLoginInterceptor(UserService userService) {
        this.userService = userService;
    }

    // Método para validar el JWT
    // tiene 3 partes: el encabezado, el cuerpo (claims) y la firma
    private Claims validateJwt(String jwt) throws JwtException {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(jwt)
                .getBody();
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {

        HttpSession session = request.getSession(true);
        if (session.getAttribute(Constants.USER_SESSION) != null || request.getCookies() == null) {
            return true;
        }
        for (Cookie c : request.getCookies()) {
            if (Constants.PERSISTENT_USER_COOKIE.equals(c.getName())) {
                String jwt = c.getValue(); // Se obtiene el valor de la cookie
                if (jwt == null) {// Comprueba si tiene algun valor asociado
                    continue;
                }
                try {
                    // logger.info(jwt);
                    Claims claims = validateJwt(jwt);// Se valida el JWT usando la clave secreta
                    String email = claims.get("email", String.class);
                    // Validar si el tipo de objeto es permitido
                    if (!"UserInfo".equals(claims.getSubject())) {
                        throw new SecurityException("Invalid object type");
                    }
                    User user = userService.findByEmail(email);
                    if (user != null) {
                        session.setAttribute(Constants.USER_SESSION, user);
                    }
                } catch (JwtException e) {
                    logger.warn("Invalid JWT token");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                    return false;
                }
            }
        }
        return true;
    }
}
