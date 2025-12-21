package com.example.authservice.utils.annotations;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.web.multipart.MultipartFile;
public class CsvValidator implements ConstraintValidator<ValidCsvFile,MultipartFile> {
    @Override
    public boolean isValid(MultipartFile file, ConstraintValidatorContext context) {
        if (file == null || file.isEmpty()) {
            return false;
        }
        String fileName = file.getOriginalFilename();
        if(fileName == null){
            return false;
        }
        return fileName.toLowerCase().endsWith(".csv");
    }
}
