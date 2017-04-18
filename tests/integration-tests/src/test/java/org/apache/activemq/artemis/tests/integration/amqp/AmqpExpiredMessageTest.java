/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.activemq.artemis.tests.integration.amqp;

import java.util.concurrent.TimeUnit;

import org.apache.activemq.artemis.core.server.Queue;
import org.apache.activemq.transport.amqp.client.AmqpClient;
import org.apache.activemq.transport.amqp.client.AmqpConnection;
import org.apache.activemq.transport.amqp.client.AmqpMessage;
import org.apache.activemq.transport.amqp.client.AmqpReceiver;
import org.apache.activemq.transport.amqp.client.AmqpSender;
import org.apache.activemq.transport.amqp.client.AmqpSession;
import org.junit.Test;

public class AmqpExpiredMessageTest extends AmqpClientTestSupport {

   @Test(timeout = 60000)
   public void testSendMessageThatIsAlreadyExpiredUsingAbsoluteTime() throws Exception {
      AmqpClient client = createAmqpClient();
      AmqpConnection connection = addConnection(client.connect());
      AmqpSession session = connection.createSession();

      AmqpSender sender = session.createSender(getQueueName());

      // Get the Queue View early to avoid racing the delivery.
      final Queue queueView = getProxyToQueue(getQueueName());
      assertNotNull(queueView);

      AmqpMessage message = new AmqpMessage();
      message.setAbsoluteExpiryTime(System.currentTimeMillis() - 5000);
      message.setText("Test-Message");
      sender.send(message);
      sender.close();

      assertEquals(1, queueView.getMessageCount());

      // Now try and get the message
      AmqpReceiver receiver = session.createReceiver(getQueueName());
      receiver.flow(1);
      AmqpMessage received = receiver.receive(1, TimeUnit.SECONDS);
      assertNull(received);

      assertEquals(1, queueView.getMessagesExpired());

      connection.close();
   }

   @Test(timeout = 60000)
   public void testSendMessageThatIsNotExpiredUsingAbsoluteTime() throws Exception {
      AmqpClient client = createAmqpClient();
      AmqpConnection connection = addConnection(client.connect());
      AmqpSession session = connection.createSession();

      AmqpSender sender = session.createSender(getQueueName());

      // Get the Queue View early to avoid racing the delivery.
      final Queue queueView = getProxyToQueue(getQueueName());
      assertNotNull(queueView);

      AmqpMessage message = new AmqpMessage();
      message.setAbsoluteExpiryTime(System.currentTimeMillis() + 5000);
      message.setText("Test-Message");
      sender.send(message);
      sender.close();

      assertEquals(1, queueView.getMessageCount());

      // Now try and get the message
      AmqpReceiver receiver = session.createReceiver(getQueueName());
      receiver.flow(1);
      AmqpMessage received = receiver.receive(5, TimeUnit.SECONDS);
      assertNotNull(received);

      assertEquals(0, queueView.getMessagesExpired());

      connection.close();
   }

   @Test(timeout = 60000)
   public void testSendMessageThatIsExiredUsingAbsoluteTimeWithLongTTL() throws Exception {
      AmqpClient client = createAmqpClient();
      AmqpConnection connection = addConnection(client.connect());
      AmqpSession session = connection.createSession();

      AmqpSender sender = session.createSender(getQueueName());

      // Get the Queue View early to avoid racing the delivery.
      final Queue queueView = getProxyToQueue(getQueueName());
      assertNotNull(queueView);

      AmqpMessage message = new AmqpMessage();
      message.setAbsoluteExpiryTime(System.currentTimeMillis() - 5000);
      // AET should override any TTL set
      message.setTimeToLive(60000);
      message.setText("Test-Message");
      sender.send(message);
      sender.close();

      assertEquals(1, queueView.getMessageCount());

      // Now try and get the message
      AmqpReceiver receiver = session.createReceiver(getQueueName());
      receiver.flow(1);
      AmqpMessage received = receiver.receive(1, TimeUnit.SECONDS);
      assertNull(received);

      assertEquals(1, queueView.getMessagesExpired());

      connection.close();
   }

   @Test(timeout = 60000)
   public void testSendMessageThatIsExpiredUsingTTLWhenAbsoluteIsZero() throws Exception {
      AmqpClient client = createAmqpClient();
      AmqpConnection connection = addConnection(client.connect());
      AmqpSession session = connection.createSession();

      AmqpSender sender = session.createSender(getQueueName());

      // Get the Queue View early to avoid racing the delivery.
      final Queue queueView = getProxyToQueue(getQueueName());
      assertNotNull(queueView);

      AmqpMessage message = new AmqpMessage();
      message.setAbsoluteExpiryTime(0);
      // AET should override any TTL set
      message.setTimeToLive(1000);
      message.setText("Test-Message");
      sender.send(message);
      sender.close();

      assertEquals(1, queueView.getMessageCount());

      Thread.sleep(1000);

      // Now try and get the message
      AmqpReceiver receiver = session.createReceiver(getQueueName());
      receiver.flow(1);
      AmqpMessage received = receiver.receive(1, TimeUnit.SECONDS);
      assertNull(received);

      assertEquals(1, queueView.getMessagesExpired());

      connection.close();
   }

   @Test(timeout = 60000)
   public void testSendMessageThatIsNotExpiredUsingAbsoluteTimeWithElspsedTTL() throws Exception {
      AmqpClient client = createAmqpClient();
      AmqpConnection connection = addConnection(client.connect());
      AmqpSession session = connection.createSession();

      AmqpSender sender = session.createSender(getQueueName());

      // Get the Queue View early to avoid racing the delivery.
      final Queue queueView = getProxyToQueue(getQueueName());
      assertNotNull(queueView);

      AmqpMessage message = new AmqpMessage();
      message.setAbsoluteExpiryTime(System.currentTimeMillis() + 5000);
      // AET should override any TTL set
      message.setTimeToLive(10);
      message.setText("Test-Message");
      sender.send(message);
      sender.close();

      Thread.sleep(50);

      assertEquals(1, queueView.getMessageCount());

      // Now try and get the message
      AmqpReceiver receiver = session.createReceiver(getQueueName());
      receiver.flow(1);
      AmqpMessage received = receiver.receive(5, TimeUnit.SECONDS);
      assertNotNull(received);

      assertEquals(0, queueView.getMessagesExpired());

      connection.close();
   }

   @Test(timeout = 60000)
   public void testSendMessageThatIsNotExpiredUsingTimeToLive() throws Exception {
      AmqpClient client = createAmqpClient();
      AmqpConnection connection = addConnection(client.connect());
      AmqpSession session = connection.createSession();

      AmqpSender sender = session.createSender(getQueueName());

      // Get the Queue View early to avoid racing the delivery.
      final Queue queueView = getProxyToQueue(getQueueName());
      assertNotNull(queueView);

      AmqpMessage message = new AmqpMessage();
      message.setTimeToLive(5000);
      message.setText("Test-Message");
      sender.send(message);
      sender.close();

      assertEquals(1, queueView.getMessageCount());

      // Now try and get the message
      AmqpReceiver receiver = session.createReceiver(getQueueName());
      receiver.flow(1);
      AmqpMessage received = receiver.receive(5, TimeUnit.SECONDS);
      assertNotNull(received);

      assertEquals(0, queueView.getMessagesExpired());

      connection.close();
   }

   @Test(timeout = 60000)
   public void testSendMessageThenAllowToExpiredUsingTimeToLive() throws Exception {
      AmqpClient client = createAmqpClient();
      AmqpConnection connection = addConnection(client.connect());
      AmqpSession session = connection.createSession();

      AmqpSender sender = session.createSender(getQueueName());

      // Get the Queue View early to avoid racing the delivery.
      final Queue queueView = getProxyToQueue(getQueueName());
      assertNotNull(queueView);

      AmqpMessage message = new AmqpMessage();
      message.setTimeToLive(10);
      message.setText("Test-Message");
      sender.send(message);
      sender.close();

      Thread.sleep(50);

      assertEquals(1, queueView.getMessageCount());

      // Now try and get the message
      AmqpReceiver receiver = session.createReceiver(getQueueName());
      receiver.flow(1);
      AmqpMessage received = receiver.receive(1, TimeUnit.SECONDS);
      assertNull(received);

      assertEquals(1, queueView.getMessagesExpired());

      connection.close();
   }
}
