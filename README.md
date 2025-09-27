# MeCare Microservices

Microservices architecture for the MeCare application — providing modular, scalable, and maintainable backend services.

---

## Table of Contents

1. [Overview](#overview)  
2. [Architecture & Components](#architecture--components)  
3. [Technologies Used](#technologies-used)  
4. [Setup & Running Locally](#setup--running-locally)  
5. [Service Details](#service-details)  
6. [API Gateway & Routing](#api-gateway--routing)  
7. [Service Discovery / Registry](#service-discovery--registry)  
8. [Docker / Docker Compose](#docker--docker-compose)  
9. [Configuration & Environment Variables](#configuration--environment-variables)  
10. [Testing](#testing)  
11. [Deployment Considerations](#deployment-considerations)  
12. [Contributing](#contributing)  
13. [License](#license)  
14. [Acknowledgments](#acknowledgments)

---

## Overview

The **MeCare Microservices** project splits the monolithic MeCare application into separate services. Each service is responsible for a distinct domain (e.g. authentication, user management, etc.). This enables independent scaling, deployment, and team autonomy.

---

## Architecture & Components

At a high level, your repo contains:

- `api-gateway` — routes external requests to the appropriate internal services  
- `auth-service` — handles user authentication, token generation, login/logout  
- `service-registry` — for service discovery (e.g. Eureka or similar)  
- `docker-compose.dev.yml` — to orchestrate all services locally  

You might also have more services (e.g. user service, product service) to expand later.

---

## Technologies Used

Here are the main technologies and frameworks you’re (or likely) using:

| Layer | Technology / Framework |
|---|---|
| Language | Java |
| Framework | Spring Boot (for microservices) |
| API Gateway | Spring Cloud Gateway / Zuul / equivalent |
| Service Registry | Spring Cloud Netflix Eureka / Consul / equivalent |
| Inter-service communication | REST / Feign Clients / HTTP |
| Containerization | Docker |
| Orchestration (local) | Docker Compose |
| Config / Environment | `application.yml` / properties / environment variables |

_(You can adjust this table to match your exact stack)_

---

## Setup & Running Locally

Below is a guide to get the project running on your local machine:

1. Clone the repository:
   ```bash
   git clone https://github.com/Sahilmaliya88/mecare-microservices.git
   cd mecare-microservices
