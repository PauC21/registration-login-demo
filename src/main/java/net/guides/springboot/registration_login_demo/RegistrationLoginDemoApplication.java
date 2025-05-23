package net.guides.springboot.registration_login_demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class RegistrationLoginDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(RegistrationLoginDemoApplication.class, args);
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String encoded = encoder.encode("1234Segura");
		System.out.println(encoded);
	}

}
