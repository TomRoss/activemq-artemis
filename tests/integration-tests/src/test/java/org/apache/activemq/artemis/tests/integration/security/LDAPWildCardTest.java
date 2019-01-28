/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.activemq.artemis.tests.integration.security;

import org.apache.activemq.artemis.api.core.ActiveMQException;
import org.apache.activemq.artemis.api.core.ActiveMQSecurityException;
import org.apache.activemq.artemis.api.core.RoutingType;
import org.apache.activemq.artemis.api.core.SimpleString;
import org.apache.activemq.artemis.api.core.TransportConfiguration;
import org.apache.activemq.artemis.api.core.client.*;
import org.apache.activemq.artemis.api.core.management.ActiveMQServerControl;
import org.apache.activemq.artemis.core.config.Configuration;
import org.apache.activemq.artemis.core.config.impl.ConfigurationImpl;
import org.apache.activemq.artemis.core.remoting.impl.invm.InVMAcceptorFactory;
import org.apache.activemq.artemis.core.remoting.impl.invm.InVMConnectorFactory;
import org.apache.activemq.artemis.core.security.Role;
import org.apache.activemq.artemis.core.server.ActiveMQServer;
import org.apache.activemq.artemis.core.server.ActiveMQServers;
import org.apache.activemq.artemis.core.server.SecuritySettingPlugin;
import org.apache.activemq.artemis.core.server.impl.LegacyLDAPSecuritySettingPlugin;
import org.apache.activemq.artemis.core.settings.HierarchicalRepository;
import org.apache.activemq.artemis.spi.core.security.ActiveMQJAASSecurityManager;
import org.apache.activemq.artemis.tests.util.ActiveMQTestBase;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import org.jboss.logging.Logger;
import org.junit.runners.MethodSorters;

import javax.naming.Context;
import javax.naming.NameClassPair;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.File;
import java.lang.management.ManagementFactory;
import java.net.URL;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.HashSet;
import java.util.Set;

import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import org.junit.Assert;


@RunWith(FrameworkRunner.class)
@CreateLdapServer(transports = {@CreateTransport(protocol = "LDAP", port = 1024, address = "localhost")})
@ApplyLdifFiles("wildcard-test-ldap.ldif")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LDAPWildCardTest extends AbstractLdapTestUnit {
   private static final Logger LOG = Logger.getLogger(LDAPWildCardTest.class);
   private static final String TARGET_TMP = "./target/tmp";
   private static final String PRINCIPAL = "uid=admin,ou=system";
   private static final String CREDENTIALS = "secret";

   private ServerLocator locator;
   private ActiveMQServer server;
   private String testDir;

   @Rule
   public TemporaryFolder temporaryFolder;


   static {
      String path = System.getProperty("java.security.auth.login.config");
      if (path == null) {
         URL resource = LDAPSecurityTest.class.getClassLoader().getResource("ldap-login.config");
         if (resource != null) {
            path = resource.getFile();
            System.setProperty("java.security.auth.login.config", path);
         }
      }
   }

   public LDAPWildCardTest() {
      File parent = new File(TARGET_TMP);
      parent.mkdirs();
      temporaryFolder = new TemporaryFolder(parent);
   }

   @Before
   public void setUp() throws Exception {
      LOG.info("Test setup.");

      Map<String, String> map = new HashMap<>();
      LegacyLDAPSecuritySettingPlugin legacyLDAPSecuritySettingPlugin = new LegacyLDAPSecuritySettingPlugin();
      map.put(LegacyLDAPSecuritySettingPlugin.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
      map.put(LegacyLDAPSecuritySettingPlugin.CONNECTION_URL, "ldap://localhost:1024");
      map.put(LegacyLDAPSecuritySettingPlugin.CONNECTION_USERNAME, "uid=admin,ou=system");
      map.put(LegacyLDAPSecuritySettingPlugin.CONNECTION_PASSWORD, "secret");
      map.put(LegacyLDAPSecuritySettingPlugin.CONNECTION_PROTOCOL, "s");
      map.put(LegacyLDAPSecuritySettingPlugin.AUTHENTICATION, "simple");
      map.put(LegacyLDAPSecuritySettingPlugin.ENABLE_LISTENER, "true");
      legacyLDAPSecuritySettingPlugin.init(map);

      locator = ActiveMQClient.createServerLocatorWithoutHA(new TransportConfiguration(InVMConnectorFactory.class.getCanonicalName()));

      testDir = temporaryFolder.getRoot().getAbsolutePath();

      ActiveMQJAASSecurityManager securityManager = new ActiveMQJAASSecurityManager("activemq");

      Configuration configuration = new ConfigurationImpl().setSecurityEnabled(true).addAcceptorConfiguration(new TransportConfiguration(InVMAcceptorFactory.class.getCanonicalName())).setJournalDirectory(ActiveMQTestBase.getJournalDir(testDir, 0, false)).setBindingsDirectory(ActiveMQTestBase.getBindingsDir(testDir, 0, false)).setPagingDirectory(ActiveMQTestBase.getPageDir(testDir, 0, false)).setLargeMessagesDirectory(ActiveMQTestBase.getLargeMessagesDir(testDir, 0, false)).setPersistenceEnabled(false).addSecuritySettingPlugin(legacyLDAPSecuritySettingPlugin);

      server = ActiveMQServers.newActiveMQServer(configuration, ManagementFactory.getPlatformMBeanServer(), securityManager, false);

      LOG.info("LDAP and broker setup completed.");
   }

   @After
   public void tearDown() throws Exception {
      LOG.info("Test teardown");

      if (locator != null){
         locator.close();
      }


      if (server != null) {
         server.stop();
      }

   }

   @Test
   public void testLDAPServer() throws Exception {

      LOG.info("Running Test Case");

      Hashtable<String, String> env = new Hashtable<>();
      env.put(Context.PROVIDER_URL, "ldap://localhost:1024");
      env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
      env.put(Context.SECURITY_AUTHENTICATION, "simple");
      env.put(Context.SECURITY_PRINCIPAL, PRINCIPAL);
      env.put(Context.SECURITY_CREDENTIALS, CREDENTIALS);
      DirContext ctx = new InitialDirContext(env);

      HashSet<String> set = new HashSet<>();

      NamingEnumeration<NameClassPair> list = ctx.list("ou=system");

      while (list.hasMore()) {
         NameClassPair ncp = list.next();
         set.add(ncp.getName());
      }

      Assert.assertTrue(set.contains("uid=admin"));
      Assert.assertTrue(set.contains("ou=users"));
      Assert.assertTrue(set.contains("ou=groups"));
      Assert.assertTrue(set.contains("ou=configuration"));
      Assert.assertTrue(set.contains("prefNodeName=sysPrefRoot"));

      set.clear();
      list = null;

      list = ctx.list("o=ActiveMQ,ou=system");

      while(list.hasMore()){

         NameClassPair ncp = list.next();

         set.add(ncp.getName());
      }

      Assert.assertTrue(set.contains("ou=destinations"));
      Assert.assertTrue(set.contains("ou=users"));
      Assert.assertTrue(set.contains("ou=roles"));

      list = null;
      set.clear();

      list = ctx.list("ou=users,o=ActiveMQ,ou=system");

      while(list.hasMore()){

         NameClassPair ncp = list.next();

         set.add(ncp.getName());
      }

      Assert.assertEquals(4,set.size());
      Assert.assertTrue(set.contains("uid=userThree"));
      Assert.assertTrue(set.contains("uid=quickuser"));
      Assert.assertTrue(set.contains("uid=userOne"));
      Assert.assertTrue(set.contains("uid=userTwo"));
      //Assert.assertTrue(set.contains("uid=admin"));

      set.clear();
      list = null;

      list = ctx.list("ou=queues,ou=destinations,o=ActiveMQ,ou=system");

      while(list.hasMore()){

         NameClassPair ncp = list.next();

         set.add(ncp.getName());
      }

      Assert.assertTrue(set.contains("uid=testQueue"));
      Assert.assertTrue(set.contains("uid=queueOne"));
      Assert.assertTrue(set.contains("uid=queueTwo"));
      Assert.assertTrue(set.contains("uid=queueThree"));

      set.clear();
      list =null;

      list = ctx.list("ou=roles,o=ActiveMQ,ou=system");

      while(list.hasMore()){

         NameClassPair ncp = list.next();

         set.add(ncp.getName());
      }

      Assert.assertTrue(set.contains("cn=user-one"));
      Assert.assertTrue(set.contains("cn=user-two"));
      Assert.assertTrue(set.contains("cn=user-three"));
      Assert.assertTrue(set.contains("cn=admin"));
      ctx.close();
   }

   @Test
   public void authorizationTest() throws Exception {
      final SimpleString ADDRESS = new SimpleString("address");
      final SimpleString DURABLE_QUEUE = new SimpleString("durableQueue");
      /*Map<String, String> options = new HashMap<>();

      options.put("connectionProtocol","s");
      options.put("connectionUsername","uid=admin,ou=system");
      options.put("connectionURL","ldap://localhost:1024");
      options.put("connectionPassword","secret");
      options.put("initialContextFactory","com.sun.jndi.ldap.LdapCtxFactory");
      options.put("authentication","simple");

      SecuritySettingPlugin securitySettingPlugin = new LegacyLDAPSecuritySettingPlugin().init(options);

      server.getConfiguration().addSecuritySettingPlugin(securitySettingPlugin); */

      server.start();

      ActiveMQServerControl serverControl = server.getActiveMQServerControl();

      //serverControl.createQueue("testQueue","testQueue",true,"MULTICAST");

      serverControl.createQueue("queueOne","queueOne",true,"MULTICAST");

      serverControl.createQueue("queueTwo","qeueueTwo",true,"MULTICAST");

      serverControl.createQueue("queueThree","queueThree",true,"MULTICAST");

      serverControl.createQueue("test.foo","test.foo",true,"MULTICAST");

      String[] addresses = serverControl.getAddressNames();

      // activemq.notification address too
      Assert.assertTrue(addresses.length == 5);

      ClientSessionFactory cf = null;
      ClientSession session = null;
      ClientProducer producer = null;
      ClientConsumer consumer = null;
      ClientMessage clientMessage = null;
      String queueName = "queueOne";

      // testing userOne

      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("userOne", "userone+", false, true, true, true, 0);

         session.start();

         producer = session.createProducer();

         consumer = session.createConsumer(queueName);

         producer.send(queueName, session.createMessage(true));


         clientMessage = consumer.receive(25000);

         Assert.assertTrue(clientMessage != null);

         producer.close();

         consumer.close();

         session.close();

         producer = null;

         session = null;

      } catch (ActiveMQException e) {

         LOG.errorf(e, "Error in test");

         Assert.fail("should not throw exception");

      } finally {

         if (cf != null) {

            cf.close();

         }
      }

         // testing userTwo
      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("userTwo", "usertwo+", false, true, true, true, 0);

         producer = session.createProducer();

         producer.send("queueTwo",session.createMessage(true));

         producer.close();

         session.close();

         producer = null;

         session = null;

      } catch (ActiveMQException e) {

         LOG.errorf(e, "Error in test");

         Assert.fail("should not throw exception");

      } finally {

         if ( cf != null) {

            cf.close();

         }
      }

      // testing userThree
      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("userThree", "userthree+", false, true, true, false, 0);

         producer = session.createProducer();

         producer.send("queueThree",session.createMessage(true));

         producer.close();

         session.close();

         producer = null;

            session = null;

         } catch (ActiveMQException e) {

            LOG.errorf(e, "Error in test");

            Assert.fail("should not throw exception");

         } finally {

            if ( cf != null) {

               cf.close();

            }
         }

      // testing quickuser autocreate destination
      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("quickuser", "quick123+", false, true, true, false, 0);

         producer = session.createProducer();

         producer.send("testQueue",session.createMessage(true));

         producer.close();

         session.close();

         producer = null;

         session = null;

      } catch (ActiveMQException e) {

         LOG.errorf(e, "Error in test");

         Assert.fail("should not throw exception");

      } finally {

         if ( cf != null) {

            cf.close();

         }
      }


   }

   @Test
   public void authenticationFailureTest() throws Exception{

      server.start();
      ClientSessionFactory cf = null;
      ClientSession session = null;

      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("quickuser", "quick123", false, true, true, false, 0);

         session.close();

      } catch (ActiveMQSecurityException securityException)  {

         LOG.errorf(securityException,"Can't authenticate quickuser - test passed");

      } catch (ActiveMQException e) {

         LOG.errorf(e,"Error in test quickuser - test failed.");

         Assert.fail("should not throw exception.");

      } finally {

         if (cf != null) {

            cf.close();

         }

      }
   }

   @Test
   public void authenticationTest() throws Exception {

      server.start();
      ClientSessionFactory cf = null;
      ClientSession session = null;

      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("quickuser", "quick123+", false, true, true, false, 0);

         session.close();

      } catch (ActiveMQException e) {

         LOG.errorf(e,"Error in test quickuser");

         Assert.fail("should not throw exception");

      } finally {

         if (cf != null) {

            cf.close();

         }

      }


      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("userOne", "userone+", false, true, true, false, 0);

         session.close();

         session = null;

      } catch (ActiveMQSecurityException securityEsxception) {

         LOG.errorf(securityEsxception,"Cannot authenticate user userOne");

      } catch (ActiveMQException e) {

         LOG.errorf(e,"Error in test userOne");

         Assert.fail("should not throw exception");

      } finally {

         if (cf != null) {

            cf.close();

         }

      }



      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("userTwo", "usertwo+", false, true, true, false, 0);

         session.close();

         session = null;

      } catch (ActiveMQException e) {

         LOG.errorf(e,"Error in test userTwo");

         Assert.fail("should not throw exception");

      } finally {

         if (cf != null) {

            cf.close();

         }

      }



      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("userThree", "userthree+", false, true, true, false, 0);

         session.close();

         session = null;

      } catch (ActiveMQException e) {

         LOG.errorf(e,"Error in test userThree");

         Assert.fail("should not throw exception");

      } finally {

         if (cf != null) {

            cf.close();

         }

      }

   }

   @Test
   public void authorizationFailureTest() throws Exception {

      server.start();

      ActiveMQServerControl serverControl = server.getActiveMQServerControl();

      serverControl.createQueue("queueOne","queueOne",true,"MULTICAST");

      serverControl.createQueue("queueTwo","qeueueTwo",true,"MULTICAST");

      serverControl.createQueue("queueThree","queueThree",true,"MULTICAST");

      String[] addresses = serverControl.getAddressNames();

      // activemq.notification address too
      Assert.assertTrue(addresses.length == 4);

      ClientSessionFactory cf = null;
      ClientSession session = null;
      ClientProducer producer = null;
      ClientConsumer consumer = null;
      ClientMessage clientMessage = null;
      String queueName = "queueTwo";

      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("userOne", "userone+", false, true, true, true, 0);

         session.start();

         producer = session.createProducer();

         consumer = session.createConsumer(queueName);

         producer.send(queueName, session.createMessage(true));


         clientMessage = consumer.receive(25000);

         Assert.assertTrue(clientMessage != null);

         producer.close();

         consumer.close();

         session.close();

         producer = null;

         session = null;

      } catch (ActiveMQException activeMQException){

         LOG.errorf(activeMQException,"Authorization failure - test passed.");

      }
   }


   @Test
   public void wildCardAuthorizationTest() throws Exception {
      final SimpleString ADDRESS = new SimpleString("address");
      final SimpleString DURABLE_QUEUE = new SimpleString("durableQueue");
      /*Map<String, String> options = new HashMap<>();

      options.put("connectionProtocol","s");
      options.put("connectionUsername","uid=admin,ou=system");
      options.put("connectionURL","ldap://localhost:1024");
      options.put("connectionPassword","secret");
      options.put("initialContextFactory","com.sun.jndi.ldap.LdapCtxFactory");
      options.put("authentication","simple");

      SecuritySettingPlugin securitySettingPlugin = new LegacyLDAPSecuritySettingPlugin().init(options);

      server.getConfiguration().addSecuritySettingPlugin(securitySettingPlugin); */

      server.start();

      ActiveMQServerControl serverControl = server.getActiveMQServerControl();

      //serverControl.createQueue("testQueue","testQueue",true,"MULTICAST");

      serverControl.createQueue("queueOne","queueOne",true,"MULTICAST");

      serverControl.createQueue("queueTwo","qeueueTwo",true,"MULTICAST");

      serverControl.createQueue("queueThree","queueThree",true,"MULTICAST");

      serverControl.createQueue("test.foo","test.foo",true,"MULTICAST");

      String[] addresses = serverControl.getAddressNames();

      // activemq.notification address too
      Assert.assertTrue(addresses.length == 5);

      ClientSessionFactory cf = null;
      ClientSession session = null;
      ClientProducer producer = null;
      ClientConsumer consumer = null;
      ClientMessage clientMessage = null;
      String queueName = "queueOne";
      // testing quickuser autocreate destination
      try {

         cf = locator.createSessionFactory();

         session = cf.createSession("quickuser", "quick123+", false, true, true, false, 0);

         producer = session.createProducer();

         producer.send("test.foo",session.createMessage(true));

         producer.close();

         session.close();

         producer = null;

         session = null;

      } catch (ActiveMQException e) {

         LOG.errorf(e, "Error in test");

         Assert.fail("should not throw exception");

      } finally {

         if ( cf != null) {

            cf.close();

         }
      }
   }

   public void init() {

   }

   public void shutdown() {
   }
}
