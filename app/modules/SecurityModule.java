package modules;

import be.objectify.deadbolt.java.cache.HandlerCache;
import com.google.inject.AbstractModule;
import controllers.CustomAuthorizer;
import controllers.DemoHttpActionAdapter;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.auth.Authenticator;
import org.ldaptive.auth.FormatDnResolver;
import org.ldaptive.auth.PooledBindAuthenticationHandler;
import org.ldaptive.pool.*;
import org.pac4j.core.authorization.authorizer.RequireAnyRoleAuthorizer;
import org.pac4j.core.client.Clients;
import org.pac4j.core.client.direct.AnonymousClient;
import org.pac4j.core.config.Config;
import org.pac4j.http.client.direct.DirectBasicAuthClient;
import org.pac4j.http.client.direct.ParameterClient;
import org.pac4j.http.client.indirect.FormClient;
import org.pac4j.http.credentials.authenticator.test.SimpleTestUsernamePasswordAuthenticator;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.pac4j.ldap.profile.service.LdapProfileService;
import org.pac4j.play.CallbackController;
import org.pac4j.play.LogoutController;
import org.pac4j.play.deadbolt2.Pac4jHandlerCache;
import org.pac4j.play.deadbolt2.Pac4jRoleHandler;
import org.pac4j.play.store.PlayCacheSessionStore;
import org.pac4j.play.store.PlaySessionStore;
import play.Configuration;
import play.Environment;
import play.cache.CacheApi;
import java.time.Duration;

public class SecurityModule extends AbstractModule {

    public final static String JWT_SALT = "12345678901234567890123456789012";

    private final Configuration configuration;

    private static class MyPac4jRoleHandler implements Pac4jRoleHandler { }

    public SecurityModule(final Environment environment, final Configuration configuration) {
        this.configuration = configuration;
    }

    @Override
    protected void configure() {

        bind(HandlerCache.class).to(Pac4jHandlerCache.class);

        bind(Pac4jRoleHandler.class).to(MyPac4jRoleHandler.class);
        final PlayCacheSessionStore playCacheSessionStore = new PlayCacheSessionStore(getProvider(CacheApi.class));
        bind(PlaySessionStore.class).toInstance(playCacheSessionStore);

        final String baseUrl = configuration.getString("baseUrl");

        // HTTP with LDAP
        final FormClient formClient = new FormClient(baseUrl + "/loginForm", getLdapProfileService());

        // REST authent with JWT for a token passed in the url as the token parameter
        final ParameterClient parameterClient = new ParameterClient("token",
                new JwtAuthenticator(new SecretSignatureConfiguration(JWT_SALT)));
        parameterClient.setSupportGetRequest(true);
        parameterClient.setSupportPostRequest(false);

        // basic auth
        final DirectBasicAuthClient directBasicAuthClient = new DirectBasicAuthClient(new SimpleTestUsernamePasswordAuthenticator());

        final Clients clients = new Clients(baseUrl + "/callback", formClient, parameterClient, directBasicAuthClient,
                new AnonymousClient());

        final Config config = new Config(clients);
        config.addAuthorizer("admin", new RequireAnyRoleAuthorizer<>("ROLE_ADMIN"));
        config.addAuthorizer("custom", new CustomAuthorizer());
        config.setHttpActionAdapter(new DemoHttpActionAdapter());
        bind(Config.class).toInstance(config);

        // callback
        final CallbackController callbackController = new CallbackController();
        callbackController.setDefaultUrl("/");
        callbackController.setMultiProfile(true);
        bind(CallbackController.class).toInstance(callbackController);

        // logout
        final LogoutController logoutController = new LogoutController();
        logoutController.setDefaultUrl("/?defaulturlafterlogout");
        bind(LogoutController.class).toInstance(logoutController);
    }

    // custom LDAP service
    private LdapProfileService getLdapProfileService()
        {
            FormatDnResolver dnResolver = new FormatDnResolver();
            dnResolver.setFormat(this.configuration.getString("dnResolverFormat"));
            ConnectionConfig connectionConfig = new ConnectionConfig();
            connectionConfig.setConnectTimeout(Duration.ofSeconds(500));
            connectionConfig.setResponseTimeout(Duration.ofSeconds(1000));
            connectionConfig.setLdapUrl(this.configuration.getString("baseLdapUrl") + this.configuration.getInt("portLdap"));
            DefaultConnectionFactory connectionFactory = new DefaultConnectionFactory();
            connectionFactory.setConnectionConfig(connectionConfig);
            PoolConfig poolConfig = new PoolConfig();
            poolConfig.setMinPoolSize(1);
            poolConfig.setMaxPoolSize(2);
            poolConfig.setValidateOnCheckOut(true);
            poolConfig.setValidateOnCheckIn(true);
            poolConfig.setValidatePeriodically(false);
            SearchValidator searchValidator = new SearchValidator();
            IdlePruneStrategy pruneStrategy = new IdlePruneStrategy();
            BlockingConnectionPool connectionPool = new BlockingConnectionPool();
            connectionPool.setPoolConfig(poolConfig);
            connectionPool.setBlockWaitTime(Duration.ofMinutes(1000));
            connectionPool.setValidator(searchValidator);
            connectionPool.setPruneStrategy(pruneStrategy);
            connectionPool.setConnectionFactory(connectionFactory);
            connectionPool.initialize();
            PooledConnectionFactory pooledConnectionFactory = new PooledConnectionFactory();
            pooledConnectionFactory.setConnectionPool(connectionPool);
            PooledBindAuthenticationHandler handler = new PooledBindAuthenticationHandler();
            handler.setConnectionFactory(pooledConnectionFactory);
            Authenticator ldaptiveAuthenticator = new Authenticator();
            ldaptiveAuthenticator.setDnResolver(dnResolver);
            ldaptiveAuthenticator.setAuthenticationHandler(handler);

            // pac4j:

            LdapProfileService ldapProfileService  = new LdapProfileService(connectionFactory,
                                                                            ldaptiveAuthenticator,
                                                                            this.configuration.getString("attributesLdap"),
                                                                            this.configuration.getString("dnResolverFormat"));

            ldapProfileService.setUsernameAttribute(this.configuration.getString("usernameAttributeLdap"));
            return ldapProfileService;
        }
}