const express = require('express')
const request = require('request-promise')
const jwt = require('jsonwebtoken')
const jwksClient  = require('jwks-rsa')

const config = require('./config.json')
const keysClient = jwksClient({
    jwksUri: config.jwks_url
})

const app = express()

app.get('/', (req, res) => 
    res.redirect(`${config.auth_url}?response_type=code&scope=openid&client_id=${config.client_id}`))

app.get('/callback', async (req, res) => {
    try {
        const code = req.query.code
        const response = await request.post(config.token_url, {
            formData: {
                grant_type: 'authorization_code',
                client_id: config.client_id,
                client_secret: config.client_secret,
                code
            }
        })

        const respJson = JSON.parse(response)
        const id_token = respJson.id_token

        const decodedJWT = await verifyToken(id_token)

        res.end('Decoded Token ' + JSON.stringify(decodedJWT))
    } catch(e) {
        console.error(e)
        res.end('Error ' + e.toString())
    }
    
})

app.listen(process.env.PORT || 8080, () => console.log('Server Started'))

function getKey(header, callback) {
    keysClient.getSigningKey(header.kid, function(err, key) {
        if (err) {
            console.error('Error getting key', err)
        } else {
            const signingKey = key.publicKey || key.rsaPublicKey;
            console.log('signingKey', signingKey)
            callback(null, signingKey)
        }
    })
}

function verifyToken(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, getKey, {}, function(err, decoded) {
            if (err) {
                console.error('Error in JWT verify', err)
                reject(err)
            } else {
                resolve(decoded)
            }
        })
    })
}