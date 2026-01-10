package com.mecare.authservice.DTOS;

import org.springframework.web.multipart.MultipartFile;

import com.mecare.authservice.utils.annotations.ValidCsvFile;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class UploadCsvRequest {
    @Schema(description = "Csv file containing users")
    @ValidCsvFile
    private MultipartFile file;
}
