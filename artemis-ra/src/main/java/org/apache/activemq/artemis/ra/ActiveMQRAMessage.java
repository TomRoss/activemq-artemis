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
package org.apache.activemq.artemis.ra;

import javax.jms.Destination;
import javax.jms.JMSException;
import javax.jms.Message;
import java.util.Arrays;
import java.util.Enumeration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.lang.invoke.MethodHandles;

import static org.apache.activemq.artemis.utils.Preconditions.checkNotNull;

/**
 * A wrapper for a message
 */
public class ActiveMQRAMessage implements Message {

   private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

   /**
    * The message
    */
   protected Message message;

   /**
    * The session
    */
   protected ActiveMQRASession session;

   /**
    * Create a new wrapper
    *
    * @param message the message
    * @param session the session
    */
   public ActiveMQRAMessage(final Message message, final ActiveMQRASession session) {
      checkNotNull(message);
      checkNotNull(session);

      logger.trace("constructor({}, {})", message, session);

      this.message = message;
      this.session = session;
   }

   /**
    * Acknowledge
    *
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void acknowledge() throws JMSException {
      logger.trace("acknowledge()");

      session.getSession(); // Check for closed
      message.acknowledge();
   }

   /**
    * Clear body
    *
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void clearBody() throws JMSException {
      logger.trace("clearBody()");

      message.clearBody();
   }

   /**
    * Clear properties
    *
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void clearProperties() throws JMSException {
      logger.trace("clearProperties()");

      message.clearProperties();
   }

   /**
    * Get property
    *
    * @param name The name
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public boolean getBooleanProperty(final String name) throws JMSException {
      logger.trace("getBooleanProperty({})", name);

      return message.getBooleanProperty(name);
   }

   /**
    * Get property
    *
    * @param name The name
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public byte getByteProperty(final String name) throws JMSException {
      logger.trace("getByteProperty({})", name);

      return message.getByteProperty(name);
   }

   /**
    * Get property
    *
    * @param name The name
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public double getDoubleProperty(final String name) throws JMSException {
      logger.trace("getDoubleProperty({})", name);

      return message.getDoubleProperty(name);
   }

   /**
    * Get property
    *
    * @param name The name
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public float getFloatProperty(final String name) throws JMSException {
      logger.trace("getFloatProperty({})", name);

      return message.getFloatProperty(name);
   }

   /**
    * Get property
    *
    * @param name The name
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public int getIntProperty(final String name) throws JMSException {
      logger.trace("getIntProperty({})", name);

      return message.getIntProperty(name);
   }

   /**
    * Get correlation id
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public String getJMSCorrelationID() throws JMSException {
      logger.trace("getJMSCorrelationID()");

      return message.getJMSCorrelationID();
   }

   /**
    * Get correlation id
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public byte[] getJMSCorrelationIDAsBytes() throws JMSException {
      logger.trace("getJMSCorrelationIDAsBytes()");

      return message.getJMSCorrelationIDAsBytes();
   }

   /**
    * Get delivery mode
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public int getJMSDeliveryMode() throws JMSException {
      logger.trace("getJMSDeliveryMode()");

      return message.getJMSDeliveryMode();
   }

   /**
    * Get destination
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public Destination getJMSDestination() throws JMSException {
      logger.trace("getJMSDestination()");

      return message.getJMSDestination();
   }

   /**
    * Get expiration
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public long getJMSExpiration() throws JMSException {
      logger.trace("getJMSExpiration()");

      return message.getJMSExpiration();
   }

   /**
    * Get message id
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public String getJMSMessageID() throws JMSException {
      logger.trace("getJMSMessageID()");

      return message.getJMSMessageID();
   }

   /**
    * Get priority
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public int getJMSPriority() throws JMSException {
      logger.trace("getJMSPriority()");

      return message.getJMSPriority();
   }

   /**
    * Get redelivered status
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public boolean getJMSRedelivered() throws JMSException {
      logger.trace("getJMSRedelivered()");

      return message.getJMSRedelivered();
   }

   /**
    * Get reply to destination
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public Destination getJMSReplyTo() throws JMSException {
      logger.trace("getJMSReplyTo()");

      return message.getJMSReplyTo();
   }

   /**
    * Get timestamp
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public long getJMSTimestamp() throws JMSException {
      logger.trace("getJMSTimestamp()");

      return message.getJMSTimestamp();
   }

   /**
    * Get type
    *
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public String getJMSType() throws JMSException {
      logger.trace("getJMSType()");

      return message.getJMSType();
   }

   /**
    * Get property
    *
    * @param name The name
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public long getLongProperty(final String name) throws JMSException {
      logger.trace("getLongProperty({})", name);

      return message.getLongProperty(name);
   }

   /**
    * Get property
    *
    * @param name The name
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public Object getObjectProperty(final String name) throws JMSException {
      logger.trace("getObjectProperty({})", name);

      return message.getObjectProperty(name);
   }

   /**
    * Get property names
    *
    * @return The values
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public Enumeration getPropertyNames() throws JMSException {
      logger.trace("getPropertyNames()");

      return message.getPropertyNames();
   }

   /**
    * Get property
    *
    * @param name The name
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public short getShortProperty(final String name) throws JMSException {
      logger.trace("getShortProperty({})", name);

      return message.getShortProperty(name);
   }

   /**
    * Get property
    *
    * @param name The name
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public String getStringProperty(final String name) throws JMSException {
      logger.trace("getStringProperty({})", name);

      return message.getStringProperty(name);
   }

   /**
    * Do property exist
    *
    * @param name The name
    * @return The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public boolean propertyExists(final String name) throws JMSException {
      logger.trace("propertyExists({})", name);

      return message.propertyExists(name);
   }

   /**
    * Set property
    *
    * @param name  The name
    * @param value The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setBooleanProperty(final String name, final boolean value) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setBooleanProperty({}, {})", name, value);
      }

      message.setBooleanProperty(name, value);
   }

   /**
    * Set property
    *
    * @param name  The name
    * @param value The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setByteProperty(final String name, final byte value) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setByteProperty({}, {})", name, value);
      }

      message.setByteProperty(name, value);
   }

   /**
    * Set property
    *
    * @param name  The name
    * @param value The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setDoubleProperty(final String name, final double value) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setDoubleProperty({}, {})", name, value);
      }

      message.setDoubleProperty(name, value);
   }

   /**
    * Set property
    *
    * @param name  The name
    * @param value The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setFloatProperty(final String name, final float value) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setFloatProperty({}, {})", name, value);
      }

      message.setFloatProperty(name, value);
   }

   /**
    * Set property
    *
    * @param name  The name
    * @param value The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setIntProperty(final String name, final int value) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setIntProperty({}, {})", name, value);
      }

      message.setIntProperty(name, value);
   }

   /**
    * Set correlation id
    *
    * @param correlationID The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSCorrelationID(final String correlationID) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setJMSCorrelationID({})", correlationID);
      }

      message.setJMSCorrelationID(correlationID);
   }

   /**
    * Set correlation id
    *
    * @param correlationID The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSCorrelationIDAsBytes(final byte[] correlationID) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setJMSCorrelationIDAsBytes({})", Arrays.toString(correlationID));
      }

      message.setJMSCorrelationIDAsBytes(correlationID);
   }

   /**
    * Set delivery mode
    *
    * @param deliveryMode The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSDeliveryMode(final int deliveryMode) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setJMSDeliveryMode({})", deliveryMode);
      }

      message.setJMSDeliveryMode(deliveryMode);
   }

   /**
    * Set destination
    *
    * @param destination The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSDestination(final Destination destination) throws JMSException {
      logger.trace("setJMSDestination({})", destination);

      message.setJMSDestination(destination);
   }

   /**
    * Set expiration
    *
    * @param expiration The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSExpiration(final long expiration) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setJMSExpiration({})", expiration);
      }

      message.setJMSExpiration(expiration);
   }

   /**
    * Set message id
    *
    * @param id The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSMessageID(final String id) throws JMSException {
      logger.trace("setJMSMessageID({})", id);

      message.setJMSMessageID(id);
   }

   /**
    * Set priority
    *
    * @param priority The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSPriority(final int priority) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setJMSPriority({})", priority);
      }

      message.setJMSPriority(priority);
   }

   /**
    * Set redelivered status
    *
    * @param redelivered The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSRedelivered(final boolean redelivered) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setJMSRedelivered({})", redelivered);
      }

      message.setJMSRedelivered(redelivered);
   }

   /**
    * Set reply to
    *
    * @param replyTo The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSReplyTo(final Destination replyTo) throws JMSException {
      logger.trace("setJMSReplyTo({})", replyTo);

      message.setJMSReplyTo(replyTo);
   }

   /**
    * Set timestamp
    *
    * @param timestamp The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSTimestamp(final long timestamp) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setJMSTimestamp({})", timestamp);
      }

      message.setJMSTimestamp(timestamp);
   }

   /**
    * Set type
    *
    * @param type The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setJMSType(final String type) throws JMSException {
      logger.trace("setJMSType({})", type);

      message.setJMSType(type);
   }

   /**
    * Set property
    *
    * @param name  The name
    * @param value The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setLongProperty(final String name, final long value) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setLongProperty({}, {})", name, value);
      }

      message.setLongProperty(name, value);
   }

   /**
    * Set property
    *
    * @param name  The name
    * @param value The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setObjectProperty(final String name, final Object value) throws JMSException {
      logger.trace("setObjectProperty({}, {})", name, value);

      message.setObjectProperty(name, value);
   }

   /**
    * Set property
    *
    * @param name  The name
    * @param value The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setShortProperty(final String name, final short value) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setShortProperty({}, {})", name, value);
      }

      message.setShortProperty(name, value);
   }

   /**
    * Set property
    *
    * @param name  The name
    * @param value The value
    * @throws JMSException Thrown if an error occurs
    */
   @Override
   public void setStringProperty(final String name, final String value) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setStringProperty({}, {})", name, value);
      }

      message.setStringProperty(name, value);
   }

   @Override
   public long getJMSDeliveryTime() throws JMSException {
      logger.trace("getJMSDeliveryTime()");

      return message.getJMSDeliveryTime();
   }

   @Override
   public void setJMSDeliveryTime(long deliveryTime) throws JMSException {
      if (logger.isTraceEnabled()) {
         logger.trace("setJMSDeliveryTime({})", deliveryTime);
      }

      message.setJMSDeliveryTime(deliveryTime);
   }

   @Override
   public <T> T getBody(Class<T> c) throws JMSException {
      logger.trace("getBody({})", c);

      return message.getBody(c);
   }

   @Override
   public boolean isBodyAssignableTo(Class c) throws JMSException {
      logger.trace("isBodyAssignableTo({})", c);

      return message.isBodyAssignableTo(c);
   }

   /**
    * Return the hash code
    *
    * @return The hash code
    */
   @Override
   public int hashCode() {
      logger.trace("hashCode()");

      return message.hashCode();
   }

   /**
    * Check for equality
    *
    * @param object The other object
    * @return True / false
    */
   @Override
   public boolean equals(final Object object) {
      logger.trace("equals({})", object);

      if (object != null && object instanceof ActiveMQRAMessage activeMQRAMessage) {
         return message.equals(activeMQRAMessage.message);
      } else {
         return message.equals(object);
      }
   }

   /**
    * Return string representation
    *
    * @return The string
    */
   @Override
   public String toString() {
      logger.trace("toString()");

      return message.toString();
   }
}
