This is an adapted `play-pac4j-java-demo` implementing an OpenLDAP request by FormClient.

<p>
You need a configured and running LDAP server, in the<u>application.conf</u> file you can change your environment's parameters.</p>
## Start & test

Build the project and launch the Play app on [http://localhost:9000](http://localhost:9000):

    cd play-pac4j-java-demo
    bin\activator run

To test, you can call a protected url by clicking on the "Protected url by **xxx**" link, which will start the authentication process with the **xxx** provider.
