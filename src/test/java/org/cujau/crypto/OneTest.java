package org.cujau.crypto;

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.cujau.utils.StringUtil;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OneTest {
    private static final Logger LOG = LoggerFactory.getLogger( OneTest.class );

    // This method returns the available implementations for a service type
    public static String[] getCryptoImpls( String serviceType ) {
        Set result = new HashSet();

        // All all providers
        Provider[] providers = Security.getProviders();
        for ( int i = 0; i < providers.length; i++ ) {
            // Get services provided by each provider
            Set keys = providers[i].keySet();
            for ( Iterator it = keys.iterator(); it.hasNext(); ) {
                String key = (String) it.next();
                key = key.split( " " )[0];

                if ( key.startsWith( serviceType + "." ) ) {
                    result.add( key.substring( serviceType.length() + 1 ) );
                } else if ( key.startsWith( "Alg.Alias." + serviceType + "." ) ) {
                    // This is an alias
                    result.add( key.substring( serviceType.length() + 11 ) );
                }
            }
        }
        return (String[]) result.toArray( new String[result.size()] );
    }

    @Test
    public void oneTest() {
        LOG.debug( StringUtil.toString( getCryptoImpls( "Cipher" ), "\n" ) );
        
    }
}
