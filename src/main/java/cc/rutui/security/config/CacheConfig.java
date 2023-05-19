package cc.rutui.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CacheConfig {

    private static final String CACHE_NAME = "security";

    @Autowired
    private CacheManager cacheManager;

    @Bean
    public Cache cache() {
        return cacheManager.getCache(CACHE_NAME);
    }

}