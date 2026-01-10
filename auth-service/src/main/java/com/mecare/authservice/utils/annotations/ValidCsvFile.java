package com.mecare.authservice.utils.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = CsvValidator.class)
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidCsvFile {
    String message() default "Invalid file type. Only CSV files are allowed.";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
