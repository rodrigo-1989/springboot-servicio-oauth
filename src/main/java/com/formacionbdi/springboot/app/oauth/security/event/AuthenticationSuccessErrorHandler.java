package com.formacionbdi.springboot.app.oauth.security.event;

import com.formacionbdi.springboot.app.commons.usuarios.models.entity.Usuario;
import com.formacionbdi.springboot.app.oauth.services.IUsuarioService;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {
	
	 @Autowired
	private IUsuarioService usuarioService;

    private Logger log = LoggerFactory.getLogger(AuthenticationSuccessErrorHandler.class);



    @Override
    public void publishAuthenticationSuccess(Authentication authentication) {
    	if(authentication.getName().equalsIgnoreCase("frontendapp")){
            return; // si es igual a frontendapp se salen del método!
        }
        UserDetails user = (UserDetails) authentication.getPrincipal();
        String mensaje = "Success Login:"+user.getUsername();
        System.out.println(mensaje);
        log.info(mensaje);
        Usuario usuario = usuarioService.findByUsername(authentication.getName());
        if (usuario.getIntentos() !=null && usuario.getIntentos() >0){
            usuario.setIntentos(0);
            usuarioService.update(usuario, usuario.getId());
        }
    
    }

    @Override
    public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
        String mensaje = "Error Login:"+exception.getMessage();
        System.out.println(mensaje);
        log.error(mensaje);
        try{
            Usuario usuario = usuarioService.findByUsername(authentication.getName());
            if (usuario.getIntentos() == null){
                usuario.setIntentos(0);
            }
            log.info("Intentos actual es de :"+ usuario.getIntentos());
            usuario.setIntentos(usuario.getIntentos()+1);
            log.info("Intentos despues de :"+ usuario.getIntentos());
            
            if( usuario.getIntentos() >= 3){
                log.error(String.format("El usuario %s des-habilitado por maximo de intentos.",usuario.getUsername()));
                usuario.setEnabled(false);
            }
            usuarioService.update(usuario, usuario.getId());
        }catch (FeignException e){
            log.error(String.format("El usuario %s no existe en el sistma",authentication.getName()));
        }

    }
}
