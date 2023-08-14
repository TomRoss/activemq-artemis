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
package org.apache.activemq.artemis.tests.leak;

import io.github.checkleak.core.CheckLeak;
import org.apache.activemq.artemis.api.core.QueueConfiguration;
import org.apache.activemq.artemis.api.core.SimpleString;
import org.apache.activemq.artemis.api.core.client.ActiveMQClient;
import org.apache.activemq.artemis.api.core.client.ClientConsumer;
import org.apache.activemq.artemis.api.core.client.ClientSession;
import org.apache.activemq.artemis.api.core.client.ClientSessionFactory;
import org.apache.activemq.artemis.api.core.client.ServerLocator;
import org.apache.activemq.artemis.core.server.ActiveMQServer;
import org.apache.activemq.artemis.tests.util.ActiveMQTestBase;
import org.apache.activemq.artemis.utils.RandomUtil;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CoreClientLeakTest extends ActiveMQTestBase {

   ActiveMQServer server;

   @BeforeClass
   public static void beforeClass() throws Exception {
      Assume.assumeTrue(CheckLeak.isLoaded());
   }

   @Override
   @Before
   public void setUp() throws Exception {
      super.setUp();
      server = createServer(true, createDefaultConfig(1, true));
      server.getConfiguration().setJournalPoolFiles(4).setJournalMinFiles(2);
      server.start();
   }

   @Test
   public void testConsumerCreatedWithEmptyFilterString() throws Exception {

      ServerLocator locator = ActiveMQClient.createServerLocator("tcp://localhost:61616");
      SimpleString queue = RandomUtil.randomSimpleString();
      SimpleString address = RandomUtil.randomSimpleString();
      SimpleString filter = SimpleString.toSimpleString("");

      try (ClientSessionFactory sf = createSessionFactory(locator);
           ClientSession clientSession = sf.createSession()) {
         try {
            clientSession.start();
            clientSession.createQueue(new QueueConfiguration(queue).setAddress(address).setDurable(true));
            CheckLeak checkLeak = new CheckLeak();
            int initialSimpleString = 0;
            for (int i = 0; i < 500; i++) {
               ClientConsumer consumer = clientSession.createConsumer(queue, filter);
               consumer.close();
               consumer = null; // setting it to null to release the consumer earlier before the checkLeak call bellow
               if (i == 100) {
                  // getting a stable number of strings after 100 consumers created
                  initialSimpleString = checkLeak.getAllObjects(SimpleString.class).length;
               }
            }

            int lastNumberOfSimpleStrings = checkLeak.getAllObjects(SimpleString.class).length;

            // I am allowing extra 50 strings created elsewhere. it should not happen at the time I created this test but I am allowing this just in case
            if (lastNumberOfSimpleStrings > initialSimpleString + 50) {
               Assert.fail("There are " + lastNumberOfSimpleStrings + " while there was " + initialSimpleString + " SimpleString objects initially");
            }

         } finally {
            clientSession.deleteQueue(queue);
         }
      }
   }

}