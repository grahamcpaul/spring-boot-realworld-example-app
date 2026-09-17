package io.spring.api.security;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
      "spring.datasource.url=jdbc:sqlite:build/security-rules-test.db",
      "spring.graphql.graphiql.enabled=true"
    })
public class SecurityRulesIntegrationTest {

  @LocalServerPort private int port;

  @BeforeEach
  public void setUp() {
    RestAssured.port = port;
  }

  @Test
  public void public_read_endpoints_do_not_require_auth() {
    given().get("/tags").then().statusCode(200);
    given().get("/articles").then().statusCode(200);
    given().get("/articles/no-such-article").then().statusCode(404);
    given().get("/profiles/no-such-user").then().statusCode(404);
  }

  @Test
  public void protected_endpoints_return_401_without_token() {
    given().get("/articles/feed").then().statusCode(401);
    given().get("/user").then().statusCode(401);
    given()
        .contentType(ContentType.JSON)
        .body(articleBody("t", "d", "b"))
        .post("/articles")
        .then()
        .statusCode(401);
    given().header("Authorization", "Token not-a-jwt").get("/user").then().statusCode(401);
  }

  @Test
  public void register_login_and_use_token() {
    String seed = UUID.randomUUID().toString().substring(0, 8);
    String email = seed + "@example.com";
    String username = "user" + seed;

    String token =
        given()
            .contentType(ContentType.JSON)
            .body(userBody(email, username, "password"))
            .post("/users")
            .then()
            .statusCode(201)
            .body("user.email", equalTo(email))
            .body("user.token", notNullValue())
            .extract()
            .path("user.token");

    given()
        .contentType(ContentType.JSON)
        .body(Map.of("user", Map.of("email", email, "password", "password")))
        .post("/users/login")
        .then()
        .statusCode(200)
        .body("user.username", equalTo(username));

    given()
        .contentType(ContentType.JSON)
        .body(Map.of("user", Map.of("email", email, "password", "wrong")))
        .post("/users/login")
        .then()
        .statusCode(422);

    given()
        .contentType(ContentType.JSON)
        .body(userBody(email, username, "password"))
        .post("/users")
        .then()
        .statusCode(422)
        .body("errors.email", hasItem("duplicated email"));

    given()
        .header("Authorization", "Token " + token)
        .get("/user")
        .then()
        .statusCode(200)
        .body("user.username", equalTo(username));

    given()
        .header("Authorization", "Token " + token)
        .get("/articles/feed")
        .then()
        .statusCode(200)
        .body("articlesCount", equalTo(0));
  }

  @Test
  public void authenticated_article_lifecycle() {
    String seed = UUID.randomUUID().toString().substring(0, 8);
    String token =
        given()
            .contentType(ContentType.JSON)
            .body(userBody(seed + "@example.com", "author" + seed, "password"))
            .post("/users")
            .then()
            .statusCode(201)
            .extract()
            .path("user.token");

    String slug =
        given()
            .header("Authorization", "Token " + token)
            .contentType(ContentType.JSON)
            .body(articleBody("Title " + seed, "desc", "body"))
            .post("/articles")
            .then()
            .statusCode(200)
            .body("article.title", equalTo("Title " + seed))
            .extract()
            .path("article.slug");

    given().get("/articles/" + slug).then().statusCode(200).body("article.slug", equalTo(slug));

    given()
        .header("Authorization", "Token " + token)
        .contentType(ContentType.JSON)
        .body(Map.of("article", Map.of("body", "updated body")))
        .put("/articles/" + slug)
        .then()
        .statusCode(200)
        .body("article.body", equalTo("updated body"));

    given()
        .header("Authorization", "Token " + token)
        .post("/articles/" + slug + "/favorite")
        .then()
        .statusCode(200)
        .body("article.favorited", equalTo(true));

    String commentId =
        given()
            .header("Authorization", "Token " + token)
            .contentType(ContentType.JSON)
            .body(Map.of("comment", Map.of("body", "nice")))
            .post("/articles/" + slug + "/comments")
            .then()
            .statusCode(201)
            .extract()
            .path("comment.id");

    given().get("/articles/" + slug + "/comments").then().statusCode(200);

    given()
        .header("Authorization", "Token " + token)
        .delete("/articles/" + slug + "/comments/" + commentId)
        .then()
        .statusCode(204);

    given()
        .header("Authorization", "Token " + token)
        .delete("/articles/" + slug)
        .then()
        .statusCode(204);

    given().get("/articles/" + slug).then().statusCode(404);
  }

  @Test
  public void cors_preflight_is_permitted() {
    given()
        .header("Origin", "http://localhost:4100")
        .header("Access-Control-Request-Method", "POST")
        .options("/users")
        .then()
        .statusCode(200)
        .header("Access-Control-Allow-Origin", notNullValue());
  }

  @Test
  public void graphql_endpoints_are_public() {
    given().get("/graphiql").then().statusCode(200);

    given()
        .contentType(ContentType.JSON)
        .body(
            graphql("{ articles(first: 1) { pageInfo { hasNextPage } edges { node { slug } } } }"))
        .post("/graphql")
        .then()
        .statusCode(200)
        .body("data.articles", notNullValue())
        .body("errors", nullValue());

    String seed = UUID.randomUUID().toString().substring(0, 8);
    String token =
        given()
            .contentType(ContentType.JSON)
            .body(userBody(seed + "@example.com", "gql" + seed, "password"))
            .post("/users")
            .then()
            .statusCode(201)
            .extract()
            .path("user.token");

    given()
        .header("Authorization", "Token " + token)
        .contentType(ContentType.JSON)
        .body(graphql("{ me { username } }"))
        .post("/graphql")
        .then()
        .statusCode(200)
        .body("data.me.username", equalTo("gql" + seed));

    given()
        .contentType(ContentType.JSON)
        .body(
            graphql(
                "mutation { createUser(input: {email: \"bad\", username: \"\", password: \"\"})"
                    + " { ... on Error { errors { key value } } } }"))
        .post("/graphql")
        .then()
        .statusCode(200)
        .body("data.createUser.errors.key", hasItem("email"));
  }

  private static Map<String, Object> graphql(String query) {
    Map<String, Object> body = new HashMap<>();
    body.put("query", query);
    return body;
  }

  private static Map<String, Object> userBody(String email, String username, String password) {
    return Map.of("user", Map.of("email", email, "username", username, "password", password));
  }

  private static Map<String, Object> articleBody(String title, String description, String body) {
    return Map.of(
        "article",
        Map.of(
            "title",
            title,
            "description",
            description,
            "body",
            body,
            "tagList",
            java.util.List.of("test")));
  }
}
