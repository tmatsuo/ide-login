package com.google.cloud.tools.ide.login;

import com.google.common.collect.ImmutableSet;

import org.junit.Assert;
import org.junit.Test;

import java.util.Set;

public class OAuthDataTest {

  private Set<String> scopes = ImmutableSet.of("scope 1", "scope 2");
  
  private OAuthData data = new OAuthData("access token", "refresh token", "storedEmail@example.com",
      scopes, 10);

  @Test
  public void testNullable() {
    data = new OAuthData(null, null, null, null, 10);
    Assert.assertNull(data.getStoredEmail());
    Assert.assertNull(data.getRefreshToken());
    Assert.assertNull(data.getAccessToken());
    Assert.assertTrue(data.getStoredScopes().isEmpty());
  }
  
  @Test
  public void testGetStoredEmail() {
    Assert.assertEquals("storedEmail@example.com", data.getStoredEmail());
  }

  @Test
  public void testGetStoredScopes() {
    Assert.assertEquals(scopes, data.getStoredScopes());
  }

  @Test
  public void testGetAccessToken() {
    Assert.assertEquals("access token", data.getAccessToken());
  }

  @Test
  public void testGetRefreshToken() {
    Assert.assertEquals("refresh token", data.getRefreshToken());
  }

  @Test
  public void testGetAccessTokenExpiryTime() {
    Assert.assertEquals(10L, data.getAccessTokenExpiryTime());
  }
}

