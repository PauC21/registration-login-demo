package net.guides.springboot.registration_login_demo.security;

import net.guides.springboot.registration_login_demo.entity.Role;
import net.guides.springboot.registration_login_demo.entity.User;
import net.guides.springboot.registration_login_demo.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email);
        System.out.println(">> Usuario encontrado: " + user.getEmail());
        System.out.println(">> Contraseña en BD: " + user.getPassword());

        if (user == null) {
            throw new UsernameNotFoundException("Invalid username or password.");

        }
        System.out.println(">> Usuario encontrado: " + user.getEmail());
        System.out.println(">> Contraseña en BD: " + user.getPassword());

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                mapRolesToAuthorities(user.getRoles()));
    }

    private Collection < ? extends GrantedAuthority> mapRolesToAuthorities(Collection <Role> roles) {
        Collection < ? extends GrantedAuthority> mapRoles = roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
        return mapRoles;
    }
}
