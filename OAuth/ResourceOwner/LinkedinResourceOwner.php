<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use HWI\Bundle\OAuthBundle\OAuth\Response\LinkedinUserResponse;
use HWI\Bundle\OAuthBundle\OAuth\Response\PathUserResponse;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * LinkedinResourceOwner.
 *
 * @author Francisco Facioni <fran6co@gmail.com>
 * @author Joseph Bielawski <stloyd@gmail.com>
 */
class LinkedinResourceOwner extends GenericOAuth2ResourceOwner
{
    /**
     * {@inheritdoc}
     */
    protected $paths = [
        'identifier' => 'id',
        'nickname' => 'emailAddress',
        'firstname' => 'firstName',
        'lastname' => 'lastName',
        'email' => 'emailAddress',
        'profilepicture' => 'profilePicture',
    ];

    /**
     * {@inheritdoc}
     */
    public function getUserInformation(array $accessToken, array $extraParameters = [])
    {

        /** @var PathUserResponse $response */
        $response = parent::getUserInformation($accessToken, $extraParameters);


        $responseData = $response->getResponse();
        // The user info returned by /me doesn't contain the email so we make an extra request to fetch it
        $content = $this->httpRequest(
            $this->normalizeUrl($this->options['email_url'], $extraParameters),
            null,
            ['Authorization' => 'Bearer '.$accessToken['access_token']]
        );

        $emailResponse = $this->getResponseContent($content);
        if (isset($emailResponse['elements']) && \count($emailResponse['elements']) > 0) {
            $responseData['emailAddress'] = $emailResponse['elements'][0]['handle~']['emailAddress'];
        }
        // errors not handled because I don't see any relevant thing to do with them

        $response->setResponse($responseData);
        return $response;
    }

    /**
     * {@inheritdoc}
     */
    protected function doGetTokenRequest($url, array $parameters = array())
    {
        $parameters['client_id'] = $this->options['client_id'];
        $parameters['client_secret'] = $this->options['client_secret'];

        return $this->httpRequest($this->normalizeUrl($url, $parameters), null, [], 'POST');
//        return $this->httpRequest($this->normalizeUrl($url, $parameters), null, array(), HttpRequestInterface::METHOD_POST);
    }

    protected function httpRequest($url, $content = null, $headers = array(), $method = null)
    {
        // LinkedIn v2 API is supposed to require Content-Type: application/json but it works without
        // and request to get the access token doesn't seems to work with Content-Type: application/json
        // so we don't put any Content-Type header.
        // Skip the Content-Type header in GenericOAuth2ResourceOwner::httpRequest
        //
        // LinkedIn API requires to always set Content-Length in POST requests
        if ('POST' === $method) {
            $headers['Content-Length'] = \is_string($content) ? (string)\strlen($content) : '0';
        }

        return parent::httpRequest($url, $content, $headers, $method);
    }

    /**
     * {@inheritdoc}
     */
    protected function doGetUserInformationRequest($url, array $parameters = array())
    {
        // LinkedIn uses different variable as they still support OAuth1.0a
        return parent::doGetUserInformationRequest(
            str_replace('access_token', 'oauth2_access_token', $url),
            $parameters
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults(
            array(
                'scope' => 'r_liteprofile r_emailaddress',
                'authorization_url' => 'https://www.linkedin.com/oauth/v2/authorization',
                'access_token_url' => 'https://www.linkedin.com/oauth/v2/accessToken',
                'infos_url' => 'https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))',
                'email_url' => 'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))',

                'user_response_class' => LinkedinUserResponse::class,

                'csrf' => true,

                'use_bearer_authorization' => true,
            )
        );
    }
}
