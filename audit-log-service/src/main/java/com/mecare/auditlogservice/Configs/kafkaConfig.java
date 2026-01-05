package com.mecare.auditlogservice.Configs;

import org.springframework.context.annotation.Configuration;

@Configuration
public class kafkaConfig {
    // private final String BOOTSTRAP_SERVERS_CONFIG = "localhost:9094";

    // @Bean
    // public ConsumerFactory<String, Object> consumerFactory() {

    // return new DefaultKafkaConsumerFactory<>(consumerProps());
    // }

    // private Map<String, Object> consumerProps() {
    // Map<String, Object> props = new HashMap<>();
    // props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, BOOTSTRAP_SERVERS_CONFIG);
    // props.put(ConsumerConfig.GROUP_ID_CONFIG, "audit-log-service");
    // props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG,
    // StringDeserializer.class);
    // props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG,
    // org.springframework.kafka.support.serializer.JsonDeserializer.class);
    // props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
    // props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);

    // return props;

    // }

    // @Bean(name = "kafkaListenerContainerFactory")
    // public ConcurrentKafkaListenerContainerFactory<String, Object>
    // kafkaListenerContainerFactory(
    // ConsumerFactory<String, Object> consumerFactory) {

    // ConcurrentKafkaListenerContainerFactory<String, Object> factory = new
    // ConcurrentKafkaListenerContainerFactory<>();
    // factory.setConsumerFactory(consumerFactory);
    // factory.getContainerProperties()
    // .setAckMode(ContainerProperties.AckMode.MANUAL);
    // return factory;
    // }
}
