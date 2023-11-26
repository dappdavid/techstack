## Definition

Spring Security is a customizable authentication and access-control framework. It is the used mainly for securing Spring-based applications.

Its main responsibility is to authenticate and authorize incoming requests for accessing any resource, including rest API endpoints, MVC (Model-View-Controller) URLs, static resources, etc.

https://www.marcobehler.com/guides/spring-security

## Latest version

Spring security 5.4

## Features of Spring Security

Spring Security provides comprehensive support for [authentication](https://docs.spring.io/spring-security/reference/features/authentication/index.html), [authorization](https://docs.spring.io/spring-security/reference/features/authorization/index.html), and protection against [common exploits](https://docs.spring.io/spring-security/reference/features/exploits/index.html#exploits). It also provides integration with other libraries to simplify its usage.

1. Authentication: Spring Security provides a number of authentication mechanisms, including support for HTTP basic and digest authentication, LDAP, Kerberos, and more.
2. Access Control: Spring Security allows you to define fine-grained access-control rules for your application, based on user roles and permissions.
3. SecurityContext: Spring Security provides a SecurityContext object that you can use to store information about the currently authenticated user, such as their name, roles, and permissions.
4. Web Security: Spring Security provides a number of features for securing web applications, including support for HTTPs, CORS, CSRF protection, and more.
5. Method-Level Security: Spring Security allows you to specify security rules at the method level, so you can control access to specific methods in your application.
6. Integration: Spring Security integrates seamlessly with a number of other frameworks and technologies, including Spring MVC, Spring Data, and more.

## Important modules (jars) in Spring security

1. Spring Security Core: This module provides the core authentication and access-control functionality of Spring Security.
2. Spring Security Web: This module provides security support for web applications, including support for HTTPs, CORS, and CSRF protection.
3. Spring Security Config: This module provides support for Java-based configuration of Spring Security.
4. Spring Security LDAP: This module provides support for LDAP-based authentication and authorization.
5. Spring Security CAS: This module provides support for CAS (Central Authentication Service)-based authentication and authorization.
6. Spring Security SAML: This module provides support for SAML (Security Assertion Markup Language)-based authentication and authorization.
7. Spring Security OAuth2: This project provides support for OAuth 2.0 and OpenID Connect-based authentication and authorization.
8. Spring Security Test: This module provides support for testing Spring Security-based applications.

## application.properties

- **`spring.security.user.name`**: the username to use for the default user
- **`spring.security.user.password`**: the password to use for the default user
- **`spring.security.user.roles`**: the roles to assign to the default user (comma-separated)
- **`spring.security.enabled`**: a boolean value that indicates whether Spring Security is enabled (default is **`true`**)
- **`spring.security.require-ssl`**: a boolean value that indicates whether SSL is required (default is **`false`**)
- **`spring.security.headers.content-security-policy`**: the value of the **`Content-Security-Policy`** HTTP header
- **`spring.security.headers.frame-options`**: the value of the **`X-Frame-Options`** HTTP header
- **`spring.security.headers.hsts`**: the value of the **`Strict-Transport-Security`** HTTP header

## Five core concepts in Spring Security

1. Authentication

   This refers to the process of verifying the identity of the user, using the credentials provided when accessing certain restricted resources. Two steps are involved in authenticating a user, namely identification and verification. An example is logging into a website with a username and a password. This is like answering the question Who are you?

2. Authorization

   It is the ability to determine a user's authority to perform an action or to view data, assuming they have successfully logged in. This ensures that users can only access the parts of a resource that they are authorized to access. It could be thought of as an answer to the question Can a user do/read this?

3. Principal

   Currently logged-in user.

4. Granted Authority

   Permissions granted to a user. i.e what the user can do

5. Role

   Group of authorities/permissions clubbed together.


## Spring Security Filter Chain

- What is it?
    - It is responsible for intercepting incoming requests and applying a series of filters to those requests to determine whether they should be allowed to proceed.
    - The filters in the filter chain are responsible for tasks such as
        - authenticating the user
        - checking the user's authorization to access a particular resource
        - ensuring that the user's request is valid (valid csrf token).
- How does it work?
    - The filter chain is configured through the use of filters, which are Java classes that implement specific security-related logic.
    - When a request is made to a web application that is protected by Spring Security, it is passed through the filter chain, and each filter in the chain is given an opportunity to process the request.
    - The filters are typically executed in a predetermined order, and the order in which the filters are executed can be customized to suit the needs of the application.
- How to find the registered Spring Security Filters (filter chain)
    1. Look in the application's configuration files: If you are using XML-based configuration for Spring Security, the filters will be listed in the **`<http>`** element of the configuration file. If you are using Java-based configuration, you can find the filters by looking for instances of the **`Filter`** interface that have been registered with the **`HttpSecurity`** object.
    2. Use a debugger: You can use a debugger to inspect the filter chain at runtime and see which filters are registered.
    3. Use the Spring Boot Actuator: If you are using Spring Boot, you can use the Actuator to see a list of all the filters that are registered in the application. To do this, you will need to enable the **`management.endpoints.web.exposure.include`** property and include **`filters`** in the list of endpoints to expose. Then, you can make a request to the **`/actuator/filters`** endpoint to see a list of all the filters that are registered in the application.

## Some predefined filters used in spring security

- **DelegatingFilterProxy**: DelegatingFilterProxy is a filter that delegates the processing of an incoming request to a bean that is defined in the Spring application context. It is typically used to allow filters to be defined as Spring beans and to take advantage of the Spring bean lifecycle and dependency injection features.
- **FilterChainProxy**: FilterChainProxy is a filter that delegates the processing of an incoming request to a chain of filters. It is typically used to define a set of filters that should be applied to a specific URL pattern or set of URL patterns, and to allow those filters to be easily configured and managed as a group.
- **Authentication:**
    - **UsernamePasswordAuthenticationFilter**: This filter is used to authenticate users using a username and password. It is typically used in conjunction with a form-based login process, and it extracts the username and password from the login form and verifies them using an **`AuthenticationManager`**.
    - **BasicAuthenticationFilter**: This filter is used to authenticate users using HTTP Basic Authentication. It extracts the username and password from the **`Authorization`** header of the incoming request and verifies them using an **`AuthenticationManager`**.
    - **BearerTokenAuthenticationFilter**: This filter is used to authenticate users using bearer tokens, such as JSON Web Tokens (JWTs). It extracts the token from the **`Authorization`** header of the incoming request and verifies it using a **`TokenStore`**.
    - **OpenIDAuthenticationFilter**: This filter is used to authenticate users using the OpenID Connect protocol. It extracts an OpenID Connect request from the incoming request and passes it to an **`OpenIDAuthenticationProvider`** for processing.
    - **SAMLProcessingFilter**: This filter is used to authenticate users using the Security Assertion Markup Language (SAML) protocol. It extracts a SAML assertion from the incoming request and passes it to a **`SAMLAuthenticationProvider`** for processing.
- **Authorization:**
    - **InterceptUrlFilter**: This filter is used to specify which URLs should be protected and which should be open to all users. It can be configured with a set of URL patterns and access rules, and it will apply those rules to incoming requests to determine whether the request should be allowed or denied.
    - **AccessControlFilter**: This filter is used to enforce access control rules based on the authenticated user's authorities. It can be configured with a list of URL patterns and required authorities, and it will check the authenticated user's authorities to determine whether the request should be allowed or denied.
    - **AuthorizationRequestFilter**: This filter is used to extract an authorization request from an incoming request and pass it to an **`AuthorizationManager`** for processing. It is typically used in conjunction with the **`InterceptUrlFilter`** to enforce access control rules based on the authorization request.
    - **AuthorizationResponseFilter**: This filter is used to generate an authorization response based on the result of an authorization request. It is typically used in conjunction with the **`AuthorizationRequestFilter`** to handle the response to an authorization request.

## ****DefaultSecurityFilterChain****

Let’s assume you [set up Spring Security](https://www.marcobehler.com/guides/spring-security#spring-security-dependencies) correctly and then boot up your web application. You’ll see the following log message:

```java
2020-02-25 10:24:27.875  INFO 11116 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Creating filter chain: any request, [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@46320c9a, org.springframework.security.web.context.SecurityContextPersistenceFilter@4d98e41b, org.springframework.security.web.header.HeaderWriterFilter@52bd9a27, org.springframework.security.web.csrf.CsrfFilter@51c65a43, org.springframework.security.web.authentication.logout.LogoutFilter@124d26ba, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@61e86192, org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter@10980560, org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter@32256e68, org.springframework.security.web.authentication.www.BasicAuthenticationFilter@52d0f583, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@5696c927, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@5f025000, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@5e7abaf7, org.springframework.security.web.session.SessionManagementFilter@681c0ae6, org.springframework.security.web.access.ExceptionTranslationFilter@15639d09, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@4f7be6c8]|
```

If you expand that one line into a list, it looks like Spring Security does not just install *one* filter, instead it installs a whole filter chain consisting of 15 (!) different filters.

So, when an HTTPRequest comes in, it will go through *all* these 15 filters, before your request finally hits your @RestControllers. The order is important, too, starting at the top of that list and going down to the bottom.

!https://www.marcobehler.com/images/filterchain-1a.png

### **Analyzing Spring’s Default FilterChain**

It would go too far to have a detailed look at every filter of this chain, but here’s the explanations for a few of those filters. Feel free to look at [Spring Security’s source code](https://github.com/spring-projects/spring-security) to understand the other filters.

- **BasicAuthenticationFilter**: Tries to find a Basic Auth HTTP Header on the request and if found, tries to authenticate the user with the header’s username and password.
- **UsernamePasswordAuthenticationFilter**: Tries to find a username/password request parameter/POST body and if found, tries to authenticate the user with those values.
- **DefaultLoginPageGeneratingFilter**: Generates a login page for you, if you don’t explicitly disable that feature. THIS filter is why you get a default login page when enabling Spring Security.
- **DefaultLogoutPageGeneratingFilter**: Generates a logout page for you, if you don’t explicitly disable that feature.
- **FilterSecurityInterceptor**: Does your authorization.

So with these couple of filters, Spring Security provides you a login/logout page, as well as the ability to login with Basic Auth or Form Logins, as well as a couple of additional goodies like the CsrfFilter, that we are going to have a look at later.

## **How to configure : WebSecurityConfigurerAdapter**

With the latest Spring Security and/or Spring Boot versions, the way to configure Spring Security is by having a class that:

1. Is annotated with @EnableWebSecurity.
2. Extends WebSecurityConfigurer, which basically offers you a configuration DSL/methods. With those methods, you can specify what URIs in your application to protect or what exploit protections to enable/disable.

Here’s what a typical WebSecurityConfigurerAdapter looks like:

```java
@Configuration
@EnableWebSecurity // (1)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter { // (1)

  @Override
  protected void configure(HttpSecurity http) throws Exception {  // (2)
      http
        .authorizeRequests()
          .antMatchers("/", "/home").permitAll() // (3)
          .anyRequest().authenticated() // (4)
          .and()
       .formLogin() // (5)
         .loginPage("/login") // (5)
         .permitAll()
         .and()
      .logout() // (6)
        .permitAll()
        .and()
      .httpBasic(); // (7)
  }
}
```

1. A normal Spring @Configuration with the @EnableWebSecurity annotation, extending from WebSecurityConfigurerAdapter.
2. By overriding the adapter’s configure(HttpSecurity) method, you get a nice little DSL with which you can configure your FilterChain.
3. All requests going to *`/`* and *`/home`* are allowed (permitted) - the user does *not* have to authenticate. You are using an [antMatcher](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/util/AntPathMatcher.html), which means you could have also used wildcards (*, \*\*, ?) in the string.
4. Any other request needs the user to be authenticated *first*, i.e. the user needs to login.
5. You are allowing form login (username/password in a form), with a custom loginPage (*`/login`*, i.e. not Spring Security’s auto-generated one). Anyone should be able to access the login page, without having to log in first (permitAll; otherwise we would have a Catch-22!).
6. The same goes for the logout page
7. On top of that, you are also allowing Basic Auth, i.e. sending in an HTTP Basic Auth Header to authenticate.

## **How to use Spring Security’s configure DSL (configure() )**

It takes some time getting used to that DSL, but you’ll find more examples in the FAQ section: [AntMatchers: Common Examples](https://www.marcobehler.com/guides/spring-security#security-examples).

What is important for now, is that *THIS* *`configure`* method is where you specify:

1. What URLs to protect (authenticated()) and which ones are allowed (permitAll()).
2. Which authentication methods are allowed (formLogin(), httpBasic()) and how they are configured.
3. In short: your application’s complete security configuration.

**Note**: You wouldn’t have needed to immediately override the adapter’s configure method, because it comes with a pretty reasonable implementation - by default. This is what it looks like:

```java
public abstract class WebSecurityConfigurerAdapter implements
		WebSecurityConfigurer<WebSecurity> {

    protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .anyRequest().authenticated()  // (1)
                    .and()
                .formLogin().and()   // (2)
                .httpBasic();  // (3)
        }
}
```

1. To access *any* URI (*`anyRequest()`*) on your application, you need to authenticate (authenticated()).
2. Form Login (*`formLogin()`*) with default settings is enabled.
3. As is HTTP Basic authentication (*`httpBasic()`*).

## Authentication

When it comes to authentication and Spring Security you have roughly three scenarios:

1. The **default**: You *can* access the (hashed) password of the user, because you have his details (username, password) saved in e.g. a database table.
2. **Less common**: You *cannot* access the (hashed) password of the user. This is the case if your users and passwords are stored *somewhere* else, like in a 3rd party identity management product offering REST services for authentication. Think: [Atlassian Crowd](https://www.atlassian.com/software/crowd).
3. **Also popular**: You want to use OAuth2 or "Login with Google/Twitter/etc." (OpenID), likely in combination with JWT. Then none of the following applies and you should go straight to the [OAuth2 chapter](https://www.marcobehler.com/guides/spring-security#oauth2).

**Note**: Depending on your scenario, you need to specify different @Beans to get Spring Security working, otherwise you’ll end up getting pretty confusing exceptions (like a NullPointerException if you forgot to specify the PasswordEncoder).

## Authentication using **UserDetailsService: Having access to the user’s password**

Imagine you have a database table where you store your users. It has a couple of columns, but most importantly it has a username and password column, where you store the user’s hashed(!) password.

```sql
create table users (id int auto_increment primary key, username varchar(255), password varchar(255));
```

In this case Spring Security needs you to define two beans to get authentication up and running.

1. A UserDetailsService.
2. A PasswordEncoder.

Specifying a UserDetailsService is as simple as this

```java
@Bean
public UserDetailsService userDetailsService() {
    return new MyDatabaseUserDetailsService(); // (1)
}
```

MyDatabaseUserDetailsService implements UserDetailsService, a very simple interface, which consists of one method returning a UserDetails object:

```java
public class MyDatabaseUserDetailsService implements UserDetailsService {

	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { // (1)
         // 1. Load the user from the users table by username. If not found, throw UsernameNotFoundException.
         // 2. Convert/wrap the user to a UserDetails object and return it.
        return someUserDetails;
    }
}

public interface UserDetails extends Serializable { // (2)

    String getUsername();

    String getPassword();

    // <3> more methods:
    // isAccountNonExpired,isAccountNonLocked,
    // isCredentialsNonExpired,isEnabled
}
```

1. A UserDetailsService loads UserDetails via the user’s username. Note that the method takes **only** one parameter: username (not the password).
2. The UserDetails interface has methods to get the (hashed!) password and one to get the username.
3. UserDetails has even more methods, like is the account active or blocked, have the credentials expired or what permissions the user has - but we won’t cover them here.

So you can either implement these interfaces yourself, like we did above, or use existing ones that Spring Security provides.

- **Full UserDetails Workflow: HTTP Basic Authentication**

Now think back to your HTTP Basic Authentication, that means you are securing your application with Spring Security and Basic Auth. This is what happens when you specify a UserDetailsService and try to login:

1. Extract the username/password combination from the HTTP Basic Auth header in a filter. You don’t have to do anything for that, it will happen under the hood.
2. Call *your* MyDatabaseUserDetailsService to load the corresponding user from the database, wrapped as a UserDetails object, which exposes the user’s hashed password.
3. Take the extracted password from the HTTP Basic Auth header, hash it *automatically* and compare it with the hashed password from your UserDetails object. If both match, the user is successfully authenticated.

That’s all there is to it. But hold on, *how* does Spring Security hash the password from the client (step 3)? With what algorithm?

- **PasswordEncoders**

Spring Security cannot magically guess your preferred password hashing algorithm. That’s why you need to specify another @Bean, a *PasswordEncoder*. If you want to, say, use the BCrypt password hashing function (Spring Security’s default) for *all your passwords*, you would specify this @Bean in your SecurityConfig.

```java
@Bean
public BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
}
```

What if you have *multiple* password hashing algorithms, because you have some legacy users whose passwords were stored with MD5 (don’t do this), and newer ones with Bcrypt or even a third algorithm like SHA-256? Then you would use the following encoder:

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```

How does this delegating encoder work? It will look at the UserDetail’s hashed password (coming from e.g. your database table), which now has to start with a *`{prefix}`*. That prefix, is your hashing method! Your database table would then look like this:

| username | password |
| --- | --- |
| mailto:john@doe.com | {bcrypt}$2y$12$6t86Rpr3llMANhCUt26oUen2WhvXr/A89Xo9zJion8W7gWgZ/zA0C |
| mailto:my@user.com | {sha256}5ffa39f5757a0dad5dfada519d02c6b71b61ab1df51b4ed1f3beed6abe0ff5f6 |

Spring Security will:

1. Read in those passwords and strip off the prefix ( {bcrypt} or {sha256} ).
2. Depending on the prefix value, use the correct PasswordEncoder (i.e. a BCryptEncoder, or a SHA256Encoder)
3. Hash the incoming, raw password with that PasswordEncoder and compare it with the stored one.

That’s all there is to PasswordEncoders.

- **Summary: Having access to the user’s password**

The takeaway for this section is: if you are using Spring Security and have access to the user’s password, then:

1. Specify a UserDetailsService. Either a custom implementation or use and configure one that Spring Security offers.
2. Specify a PasswordEncoder.

## Authentication using ****AuthenticationProvider: Not having access to the user’s password****

Now, imagine that you are using [Atlassian Crowd](https://www.atlassian.com/software/crowd) for centralized identity management. That means all your users and passwords for all your applications are stored in Atlassian Crowd and not in your database table anymore.

This has two implications:

1. You do *not have* the user passwords anymore in your application, as you cannot ask Crowd to just give you those passwords.
2. You do, however, have a REST API that you can login against, with your username and password. (A POST request to the *`/rest/usermanagement/1/authentication`* REST endpoint).

If that is the case, you cannot use a UserDetailsService anymore, instead you need to implement and provide an **AuthenticationProvider** @Bean.

```java
@Bean
    public AuthenticationProvider authenticationProvider() {
        return new AtlassianCrowdAuthenticationProvider();
    }
```

An AuthenticationProvider consists primarily of one method and a naive implementation could look like this:

```java
public class AtlassianCrowdAuthenticationProvider implements AuthenticationProvider {

        Authentication authenticate(Authentication authentication)  // (1)
                throws AuthenticationException {
            String username = authentication.getPrincipal().toString(); // (1)
            String password = authentication.getCredentials().toString(); // (1)

            User user = callAtlassianCrowdRestService(username, password); // (2)
            if (user == null) {                                     // (3)
                throw new AuthenticationException("could not login");
            }
            return new UserNamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities()); // (4)
        }
	    // other method ignored
}
```

1. Compared to the UserDetails load() method, where you only had access to the username, you now have access to the complete authentication attempt, *usually* containing a username and password.
2. You can do whatever you want to authenticate the user, e.g. call a REST-service.
3. If authentication failed, you need to throw an exception.
4. If authentication succeeded, you need to return a fully initialized UsernamePasswordAuthenticationToken. It is an implementation of the Authentication interface and needs to have the field authenticated be set to true (which the constructor used above will automatically set). We’ll cover authorities in the next chapter
- **Full AuthenticationProvider Workflow: HTTP Basic Authentication**

Now think back to your HTTP Basic Authentication, that means you are securing your application with Spring Security and Basic Auth. This is what happens when you specify an AuthenticationProvider and try to login:

1. Extract the username/password combination from the HTTP Basic Auth header in a filter. You don’t have to do anything for that, it will happen under the hood.
2. Call *your* AuthenticationProvider (e.g. AtlassianCrowdAuthenticationProvider) with that username and password for you to do the authentication (e.g. REST call) yourself.

There is no password hashing or similar going on, as you are essentially delegating to a third-party to do the actual username/password check. That’s AuthenticationProvider authentication in a nutshell!

- **Summary: AuthenticationProvider**

The takeaway for this section is: if you are using Spring Security and *do not* have access to the user’s password, then *implement and provide an AuthenticationProvider @Bean*.

## **How do I programmatically access the currently authenticated user in Spring Security?**

As mentioned in the article, Spring Security stores the currently authenticated user (or rather a SecurityContext) in a thread-local variable inside the SecurityContextHolder. You can access it like so:

`SecurityContext context = SecurityContextHolder.getContext();
Authentication authentication = context.getAuthentication();
String username = authentication.getName();
Object principal = authentication.getPrincipal();
Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();`

Note, that Spring Security *by default* will set an *`AnonymousAuthenticationToken`* as authentication on the SecurityContextHolder, if you are not logged in. This leads to some confusion, as people would naturally expect a null value there.

## What is basic and digest authentication?

Basic authentication and digest authentication are two different ways to authenticate a user in Spring Security.

Basic authentication is a simple authentication scheme that involves sending a user's credentials (usually a username and password) in an HTTP header. It is called "basic" because it is designed to be simple and easy to implement. However, it has some weaknesses, as the credentials are sent in plain text and can be easily intercepted.

Digest authentication is a more secure authentication scheme that involves sending a hash of the user's credentials instead of the credentials themselves. It is called "digest" because the credentials are hashed using a one-way hash function, which makes it more difficult for an attacker to intercept and use the credentials.

Here's a simple example of how to configure basic authentication in Spring Security:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
        .anyRequest().authenticated()
        .and()
      .httpBasic();
  }

}

```

And here's an example of how to configure digest authentication:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
        .anyRequest().authenticated()
        .and()
      .digestAuthentication()
        .userDetailsService(userDetailsService);
  }

}

```

## Role vs Authority

Roles are related to the function an employee has in a company; i.e. Administrator, Manager, Cashier, and so forth. Authorities are related to the actions that can be performed by a user such as Add users or Delete users.

So you would have roles defined such as ROLE_ADMINISTRATOR and ROLE_MANAGER which you can test using http...hasRole("ADMINISTRATOR"), and for authorities you could do something like; http...hasAuthority("ADD_USER").

## Authorization

https://www.marcobehler.com/guides/spring-security#_authorization_with_spring_security

In Spring Security, authorization refers to the process of determining what permissions an authenticated user has. It is the process of granting or denying access to specific resources or operations based on the user's privileges or roles. The purpose of authorization is to ensure that only authorized users can perform certain actions within an application.

There are several ways to implement authorization in Spring Security:

1. Role-based access control: In this approach, users are assigned to certain roles, and access to resources or operations is granted based on those roles. For example, a user with the "admin" role might have access to all resources, while a user with the "user" role might only have access to a subset of resources.

    ```java
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public void deleteUser(Long userId) {
        // delete user logic here
    }
    ```

2. Method-level security: This approach allows you to specify which roles or users are allowed to access specific methods in your application's code. For example, you might specify that only users with the "admin" role are allowed to access a particular method.

    ```java
    @Secured("ROLE_ADMIN")
    public void deleteUser(Long userId) {
        // delete user logic here
    }
    ```

3. URL-based security: In this approach, access to specific URLs is restricted based on the user's roles or privileges. For example, you might specify that only users with the "admin" role are allowed to access the "/admin" URL.

    ```java
    http.authorizeRequests()
       .antMatchers("/admin/**").hasRole("ADMIN")
       .anyRequest().permitAll();
    ```

4. Expression-based security: This approach allows you to use expressions to specify which users or roles are allowed to access specific resources or operations. For example, you might use an expression to specify that only users with the "admin" role are allowed to access a particular resource.

    ```java
    @PreAuthorize("hasPermission(#user, 'update')")
    public void updateUser(User user) {
        // update user logic here
    }
    ```


## Annotations in SpringSecurity for Authorization

- @Secured & @RolesAllowed

  **`@Secured`** is a Spring-specific annotation and is used to secure methods and classes in a Spring application. It allows you to specify one or more roles that are allowed to access the annotated element.

  **`@RolesAllowed`** is a Java standard annotation, defined in the **`javax.annotation.security`** package, that serves the same purpose as **`@Secured`** but can be used in any Java application, not just Spring applications. It also allows you to specify one or more roles that are allowed to access the annotated element.

  Both annotations take in an authority/role string as value.

- @PreAuthorize/@PostAuthorize

  They are also (newer) Spring specific annotations and more powerful than the @Secured & @RolesAllowed annotations, as they can contain not only authorities/roles, but also *any* valid SpEL expression.

  **`@PreAuthorize`** is used to check the authorization of a user before an action is performed, while **`@PostAuthorize`** is used to check the authorization of a user after an action is performed. The difference is mainly when the check is done.

  One scenario where you might use **`@PostAuthorize`** over **`@PreAuthorize`** is when you need to check if a user has the appropriate permissions to access a resource after it has been retrieved.

  For example, imagine you have a method that retrieves a sensitive document from a database, and you want to ensure that only users with the "VIEW_SENSITIVE_DOCUMENTS" role are able to see it


To start off, you can always use @Secured and switch to @PreAuthorize as soon as the need arises.

All these annotations will raise an *`AccessDeniedException`* if you try and access a protected method with an insufficient authority/role.

## Session management in Spring Security.

Spring Security provides a number of ways to manage user sessions, including the following:

- **`ConcurrentSessionControlAuthenticationStrategy`**: This strategy allows you to limit the number of concurrent sessions that a user can have with the application. It is useful for preventing a single user from using the same credentials to log in from multiple devices at the same time.
- **`SessionAuthenticationStrategy`**: This strategy is responsible for handling the creation and destruction of user sessions. It can be used to implement custom session management policies, such as session fixation protection or session timeout.
- **`SessionRegistry`**: This is a registry that stores information about all of the active user sessions in the application. It can be used to enumerate all of the active sessions for a particular user, or to invalidate all of the sessions for a user when necessary.

Here is an example of how to use the **`ConcurrentSessionControlAuthenticationStrategy`** to limit the number of concurrent sessions for a user:

```java
@Autowired
private SessionRegistry sessionRegistry;

@Override
protected void configure(HttpSecurity http) throws Exception {
  http
      .sessionManagement()
      .maximumSessions(1)
      .sessionRegistry(sessionRegistry)
      .and()
      .and()
      .authorizeRequests()
      .anyRequest().authenticated()
      .and()
      .formLogin();
}

```

## Method security using Spring Security

Method security in Spring Security refers to the process of securing access to methods in a Java class based on the current authenticated user's roles and permissions. This can be useful for enforcing fine-grained access control in an application.

To use method security in Spring Security, you will need to enable it in your configuration and use Spring Security's **`@Secured`** or **`@PreAuthorize`** annotations to specify which methods should be secured.

Here is an example of how to enable method security in a Spring Security configuration:

```java
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
}

```

Once method security is enabled, you can use the **`@Secured`** annotation to specify which methods should be secured. The **`@Secured`** annotation takes a list of security roles as an argument, and the method will only be accessible to users who have at least one of the specified roles.

Here is an example of using the **`@Secured`** annotation:

```java
@Secured("ROLE_ADMIN")
public void deleteUser(String username) {
  // Code to delete the user goes here
}

```

You can also use the **`@PreAuthorize`** annotation to specify more complex security expressions. The **`@PreAuthorize`** annotation takes an expression as an argument, and the method will only be accessible if the expression evaluates to **`true`**.

Here is an example of using the **`@PreAuthorize`** annotation:

```java
@PreAuthorize("hasRole('ROLE_ADMIN') and hasPermission(#user, 'delete')")
public void deleteUser(User user) {
  // Code to delete the user goes here
}
```

## HASHING in spring security

Hashing is often used in security applications to protect sensitive data, such as passwords, from being stolen or compromised. By hashing the password before storing it, an attacker who gains access to the hashed password will not be able to use it to log in to the system, as they do not have the original password.

The hash value is generated using a one-way hash function, which means that it is not possible to recreate the original data from the hash value. This makes it more secure to store the hash value instead of the original data, as it is much harder for an attacker to obtain the original data from the hash value.

Hashing passwords need to have four main properties to be secure:

1. It should be *deterministic*: the same message processed by the same hash function should *always* produce the same *hash*
2. It's not *reversible*: it's impractical to generate a *message* from its *hash*
3. It has high *[entropy](https://www.baeldung.com/cs/cs-entropy-definition)*: a small change to a *message* should produce a vastly different *hash*
4. And it resists *collisions*: two different *messages* should not produce the same *hash*

To use the SHA-256 hash function to hash passwords in Spring Security, you can use the **`MessageDigest`** class. Here's a simple code example that illustrates how to do this:

```java
@Service
public class PasswordService {

  private final Random random = new SecureRandom();

  public String generateSalt() {
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    return Base64.getEncoder().encodeToString(salt);
  }

  public String hashPassword(String password, String salt) {
    try {
      byte[] saltBytes = Base64.getDecoder().decode(salt);
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      messageDigest.update(saltBytes);
      byte[] hashedPassword = messageDigest.digest(password.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(hashedPassword);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Error hashing password", e);
    }
  }

}

```

In this example, the **`generateSalt()`** method is the same as before, but the **`hashPassword()`** method has been updated to use the **`MessageDigest`** class to generate a SHA-256 hash of the password. The salt value is first decoded from its base64 representation and then passed to the **`update()`** method of the **`MessageDigest`** object, which incorporates it into the hash. Finally, the hashed password is returned as a base64-encoded string.

To use this password service in your Spring Security application, you can inject it into your authentication provider and use it to hash the user's password before storing it:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordService passwordService;

  public SecurityConfig(PasswordService passwordService) {
    this.passwordService = passwordService;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(username -> {
      User user = userRepository.findByUsername(username);
      if (user == null) {
        throw new UsernameNotFoundException("User not found");
      }
      String salt = passwordService.generateSalt();
      String hashedPassword = passwordService.hashPassword(user.getPassword(), salt);
      return new User(user.getUsername(), hashedPassword, salt, user.getRoles());
    });
  }

}
```

## Salting in Spring security

Salting is a technique used in Spring Security to enhance the security of password storage. It involves adding random data, called a "salt," to the password before hashing it. The salt is stored along with the hashed password, so that it can be used to verify the password later on.

The purpose of salting is to make it more difficult for an attacker to crack the password, even if they have access to the hashed password. Without the salt, an attacker could pre-compute hashes for common passwords and then quickly test whether a given hashed password is one of them. By adding a unique salt to each password, this pre-computation becomes much more difficult, as the attacker would have to compute a separate hash for each salt.

Here's a simple code example that illustrates how salting works in Spring Security:

```java
@Service
public class PasswordService {

  private final Random random = new SecureRandom();

  public String generateSalt() {
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    return Base64.getEncoder().encodeToString(salt);
  }

  public String hashPassword(String password, String salt) {
    try {
      byte[] saltBytes = Base64.getDecoder().decode(salt);
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      messageDigest.update(saltBytes);
      byte[] hashedPassword = messageDigest.digest(password.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(hashedPassword);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Error hashing password", e);
    }
  }

}
```

## CSRF in Spring Security

Cross-Site Request Forgery (CSRF) is a type of attack that involves tricking a user into making unintended requests to a web application. It is often used to perform unauthorized actions on behalf of the user, such as transferring money or changing the user's password.

To protect against CSRF attacks, Spring Security provides a feature called CSRF protection. This feature works by generating a unique token for each user session, and then checking that the token is included with each request made by the user. If the token is not present, or if it is not valid, the request is rejected.

Here's a simple code example that illustrates how to enable CSRF protection in Spring Security:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .csrf()
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .and()
      .authorizeRequests()
        .anyRequest().authenticated()
        .and()
      .formLogin();
  }

}

```

In this example, the **`csrf()`** method is used to enable CSRF protection and configure how it works. The **`csrfTokenRepository()`** method specifies that the CSRF token should be stored in a cookie, and the **`withHttpOnlyFalse()`** method disables the "HttpOnly" flag on the cookie, which makes it accessible to JavaScript. This will put the CSRFToken into a cookie "XSRF-TOKEN" (and send that to the browser).

To disable csrf :  `http.csrf().disable();`

## Is Spring security a cross-cutting concern?

Yes, Spring Security is a cross-cutting concern in that it is a framework that is designed to be used in multiple areas of an application. Cross-cutting concerns are functionality that is required by many different parts of an application, and they are often implemented using techniques such as aspect-oriented programming (AOP) to separate the functionality from the main business logic of the application.

Spring Security is a good example of a cross-cutting concern because it is a framework for implementing security features such as authentication, authorization, and session management. These features are typically required by many different parts of an application, and implementing them using Spring Security allows you to separate the security-related logic from the main business logic of the application. This makes it easier to maintain the application and make changes to the security features without affecting the rest of the application.

## Explain the following in SpringSecurity:

- **SecurityContext and SecurityContextHolder**:
    - The **`SecurityContext`** is an object that holds the security-related information for a single user. It includes the **`Authentication`** object, which holds the user's authentication details, as well as any other security-related information that is specific to the user.
    - The **`SecurityContextHolder`** is a class that is responsible for holding the **`SecurityContext`** for the current user. It allows you to access the **`SecurityContext`** from anywhere in the application.
- **PasswordEncoder**: A **`PasswordEncoder`** is an interface that is used to encode passwords. It is typically used to hash passwords before they are stored in a database. Spring Security provides a number of different implementations of the **`PasswordEncoder`** interface, including **`BCryptPasswordEncoder`**, **`Pbkdf2PasswordEncoder`**, and **`SCryptPasswordEncoder`**.
- **AbstractSecurityInterceptor**: The **`AbstractSecurityInterceptor`** is an abstract class that is used to implement security interceptors in Spring Security. A security interceptor is a component that is responsible for intercepting requests and enforcing security constraints. The **`AbstractSecurityInterceptor`** provides a number of methods that can be used to implement security interceptors, including **`beforeInvocation`**, **`afterInvocation`**, and **`invoke`**.
- **AuthenticationManager**: The **`AuthenticationManager`** is an interface that is used to authenticate users in Spring Security. It is responsible for verifying the user's credentials and returning an **`Authentication`** object if the credentials are valid. The **`AuthenticationManager`** is often used in conjunction with the **`AuthenticationProvider`** interface, which is responsible for verifying the user's credentials and returning an **`Authentication`** object.
- **ProviderManager**: The **`ProviderManager`** is an implementation of the **`AuthenticationManager`** interface that is used to delegate to a list of **`AuthenticationProvider`** objects to authenticate a user. It is often used as the default **`AuthenticationManager`** in Spring Security.
- **Principal**: A **`Principal`** is an object that represents the user who is currently authenticated. It is typically used to hold the user's name or identifier. In Spring Security, the **`Principal`** is often represented by the **`Authentication`** object, which holds the user's authentication details.

## What is the intercept-url pattern and why do we need it

The **`intercept-url`** pattern is an element that is used in a Spring Security configuration to specify a URL pattern that should be secured by the application. It is used to define which URLs in the application should be protected and which should be publicly accessible.

For example, you might use an **`intercept-url`** pattern to specify that all URLs that begin with "/admin" should be protected, while all other URLs should be publicly accessible:

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
  http
      .authorizeRequests()
      .antMatchers("/admin/**").authenticated()
      .anyRequest().permitAll()
      .and()
      .formLogin();
}
```

## Does order matter in the intercept-url pattern? If yes, then in which order should we write it?

Yes, the order of the **`intercept-url`** patterns in a Spring Security configuration does matter. The patterns are evaluated in the order that they are defined, and the first pattern that matches a given URL will be used to determine the security constraints for that URL.

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
  http
      .authorizeRequests()
      .antMatchers("/admin/**").hasRole("ADMIN")
      .antMatchers("/user/**").hasRole("USER")
      .anyRequest().permitAll()
      .and()
      .formLogin();
}
```

In this example, the **`intercept-url`** patterns are defined in the following order:

1. **`/admin/**`** - requires the "ADMIN" role
2. **`/user/**`** - requires the "USER" role
3. **`/**`** - permits all requests

If a request is made to the URL "/admin/foo", the first pattern will match and the request will be required to have the "ADMIN" role. If a request is made to the URL "/user/foo", the second pattern will match and the request will be required to have the "USER" role. If a request is made to any other URL, the third pattern will match and the request will be permitted.

In general, it is a good idea to order your **`intercept-url`** patterns from most specific to least specific. This will ensure that the most specific patterns are evaluated first and the correct security constraints are applied to the request.

## How to Enable HTTPS in production

Here are the steps you can follow to enable HTTPS in a Spring Security application:

1. Obtain a SSL certificate from a trusted CA. There are many options available, including paid and free options.
2. Install the SSL certificate on your server. This typically involves placing the certificate and private key files in a specific location and configuring your web server (e.g. Apache or Nginx) to use them.
3. Configure your Spring Security application to use HTTPS. This can be done by setting the **`server.ssl.enabled`** property to **`true`** in your application's configuration file (e.g. application.properties).
4. Redirect all HTTP traffic to HTTPS. This can be done by adding a redirect rule to your web server's configuration, or by using the **`HttpSecurity`** configuration in your Spring Security application.

Here's an example of how to configure HTTPS in a Spring Security application:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .requiresChannel()
        .anyRequest().requiresSecure()
        .and()
      .authorizeRequests()
        .anyRequest().authenticated()
        .and()
      .formLogin();
  }
```

## Use a content security policy (to avoid XSS attacks)

Cross-site scripting (XSS) is a type of vulnerability that allows an attacker to inject malicious code into a web page that is viewed by other users. This can be done by injecting the malicious code into an input field on the page, such as a search box or a comment form. When the page is viewed by other users, the malicious code is executed in their web browser, allowing the attacker to steal sensitive information, such as login credentials or personal data.

There are two main types of XSS attacks: reflected and stored. In a reflected XSS attack, the malicious code is included in the URL of the page, and it is executed when the URL is loaded. In a stored XSS attack, the malicious code is stored on the server and is executed every time the page is loaded.

To use a content security policy (CSP) in Spring Security to avoid cross-site scripting (XSS) attacks, you can add a **`Content-Security-Policy`** header to the HTTP response. The value of the header should be a string that specifies the CSP rules that should be applied to the response.

Here's an example of how you might configure a CSP in Spring Security:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .headers()
        .contentSecurityPolicy("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
        .and()
      .authorizeRequests()
        .anyRequest().permitAll();
  }

}
```

In this example, the **`contentSecurityPolicy()`** method is used to add a **`Content-Security-Policy`** header to the HTTP response. The value of the header is a string that specifies the CSP rules that should be applied to the response. In this case, the rules allow resources to be loaded only from the same origin (**`default-src 'self'`**) and allow inline scripts and styles (**`script-src 'self' 'unsafe-inline'`**, **`style-src 'self' 'unsafe-inline'`**).

## How to Store secrets securely

1. Use an external secrets management service: One option is to use an external secrets management service, such as Hashicorp Vault or AWS Secrets Manager, to store your secrets. These services provide secure storage for secrets and allow you to access them using APIs or CLI tools.
2. Use the Java KeyStore: Another option is to use the Java KeyStore to store your secrets. The KeyStore is a secure storage facility provided by the Java runtime, and it allows you to store sensitive information, such as passwords and encryption keys, in a password-protected file.
3. Use environment variables: You can also store your secrets as environment variables on your server and access them using the **`System.getenv()`** method in your Java code. This can be a convenient option, but it is less secure than the other options because environment variables are usually stored in plaintext on the server.
4. Use a configuration file: You can store your secrets in a configuration file, such as a **`.properties`** file, and access them using the **`@Value`** annotation in your code. This can be a convenient option, but it is less secure than the other options because the configuration file is usually stored in plaintext on the server.

## **AntMatchers: Common Examples**

A non-sensical example displaying the most useful antMatchers (and regexMatcher/mvcMatcher) possibilities:

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
      .antMatchers(*"/api/user/**"*, *"/api/ticket/**"*, *"/index"*).hasAuthority(*"ROLE_USER"*)
      .antMatchers(HttpMethod.POST, *"/forms/**"*).hasAnyRole(*"ADMIN"*, *"CALLCENTER"*)
      .antMatchers(*"/user/**"*).access(*"@webSecurity.check(authentication,request)"*);
}
```

## **How to use a custom login page with Spring Security?**

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
  http
      .authorizeRequests()
          .anyRequest().authenticated()
          .and()
      .formLogin()
          .loginPage(*"/login"*) // **(1)**.permitAll();
}
```

## **How to do a programmatic login with Spring Security?**

```java
UserDetails principal = userDetailsService.loadUserByUsername(username);
Authentication authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(), principal.getAuthorities());
SecurityContext context = SecurityContextHolder.createEmptyContext();
context.setAuthentication(authentication);
```

## **How to disable CSRF just for certain paths?**

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
      http
       .csrf().ignoringAntMatchers(*"/api/**"*);
    }
```

## Implement and explain using Spring Security (TODO)

- Login flow
- Logout flow

## Transaction Management in Spring Security (TODO)