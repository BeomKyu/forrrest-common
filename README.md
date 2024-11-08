# **Forrrest Common Module Overview**

- Forrrest Common은 마이크로서비스 아키텍처에서 공통으로 사용되는 보안 컴포넌트들을 제공하는 모듈입니다.

## *Security Features*

- Token-based Authentication
- JWT(JSON Web Token) 기반의 인증 시스템을 구현하며, 다음과 같은 토큰 타입을 지원합니다:

```
  public enum TokenType {
    USER_ACCESS,    // 일반 사용자 접근 토큰
    USER_REFRESH,   // 일반 사용자 갱신 토큰
    PROFILE_ACCESS, // 프로필 접근 토큰
    PROFILE_REFRESH,// 프로필 갱신 토큰
    NONCE          // 일회성 토큰

}
```

## *Core Components*

### 1. Token Provider
- TokenProvider 인터페이스와 JwtTokenProvider 구현체
- 토큰 생성, 검증, 파싱 등의 기능 제공
- 토큰 타입별 유효성 검사 지원


### 2. Authentication
- TokenAuthentication 추상 클래스를 기반으로 한 타입별 인증 객체:
- UserTokenAuthentication
- ProfileTokenAuthentication
- NonceTokenAuthentication
- Spring Security의 Authentication 인터페이스 구현
### 3. Filters
- AbstractTokenFilter를 상속한 토큰 타입별 필터:
- UserTokenFilter: 일반 사용자 접근 관리
- ProfileTokenFilter: 프로필 접근 관리
- NonceTokenFilter: 일회성 토큰 관리
- 설정된 경로 패턴에 따라 필터링 수행
### 4. Exception Handling
- TokenExceptionHandler를 통한 중앙 집중식 예외 처리
- 토큰 관련 예외 발생 시 적절한 HTTP 응답 생성
- Configuration
- 필터별 경로 패턴은 application.properties/yaml에서 설정:

```
security:
  token:
    user-paths: /api/users/**
    profile-paths: /api/profiles/**
    nonce-paths: /api/nonce/**
  ```
## *Usage Example*
### Security Flow
1. 클라이언트가 요청과 함께 Bearer 토큰 전송
2. 해당 경로에 맞는 필터가 토큰 검증
3. 토큰이 유효한 경우 SecurityContext에 인증 정보 설정
4. 예외 발생 시 TokenExceptionHandler가 처리
- 이 모듈은 Spring Security와 JWT를 기반으로 하며, 마이크로서비스 간 일관된 보안 정책을 제공합니다.
