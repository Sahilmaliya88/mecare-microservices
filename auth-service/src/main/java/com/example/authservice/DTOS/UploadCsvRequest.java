package com.example.authservice.DTOS;

import com.example.authservice.utils.annotations.ValidCsvFile;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class UploadCsvRequest {
    @Schema(description = "Csv file containing users")
    @ValidCsvFile
    private MultipartFile file;
}
