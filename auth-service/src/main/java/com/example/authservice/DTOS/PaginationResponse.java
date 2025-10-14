package com.example.authservice.DTOS;

import java.util.List;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PaginationResponse<T> {
    private long totalItems;
    private int totalPages;
    private int currentPageSize;
    private int pageSize;
    private List<T> data;

}
