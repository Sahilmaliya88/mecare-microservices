package com.example.authservice.utils.annotations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = CsvValidator.class)
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidCsvFile {
    String message() default "Invalid file type. Only CSV files are allowed.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
