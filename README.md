# Webshell Generator

## Description

The **Webshell Generator** was developed as part of the thesis for the Software Engineering
and Information Systems master's degree. It provides an HTTP-based API that can be used to
generate custom and secure Web Shells using a modular approach.

A client-server approach is proposed for the interaction with generated Web Shells. As such,
a client program will be generated together with the web shell. Communication between both
components will be based a stream of encrypted HTTP POST messages, so as to ensure confidentiality
on insecure networks.

Note that, while it is perfectly possible to interact directly with the apply, it is recommended
to use the [frontend component](https://github.com/david-gilarranz016/wonka-front-end) developed to
make the process easier.

Furthermore, it is recommended to make use of the docker compose file provided by the
[deployment repository](https://github.com/david-gilarranz016/wonka-deployment/) to streamline the
process of setting up the infrastructure.

## Instructions for Users

### Installation and Deployment

If the user prefers to build and deploy the application independently, the following steps must
be followed:

1. Clone the GitHub repository:

```bash
git clone https://github.com/david-gilarranz016/wonka-generator.git
cd wonka-generator.git
```

2. Build the docker image:

```bash
docker build -t wonka/api .
```

3. Run the generated docker image:

```bash
docker run -d -p 8080:8000 wonka/api
```

If the user wants to make use of the rudimentary DoS protection provided by the built-in IP address
trhottling, a `redis` server will also need to be deployed. This can be easily done by downloading
the official `redis` image from Docker Hub and deploying it locally.

```bash
docker pull redis
docker run -d redis
```

Finally, when creating the container, the environment variables `REDIS_HOST` and `REDIS_PORT` will need
to be set to the host running the `redis` server. If it is being run locally on the default port, the
following command can be issued:

```bash
docker run -d -p 8080:8000 -e REDIS_HOST=localhost -e REDIS_PORT=6379 wonka/api
```

### API Endpoints

Even though interacting with the generator using the suggested
[frontend application](https://github.com/david-gilarranz016/wonka-front-end) is preferred,
it is still possible to manually interact with the API and successfully generate a customized Web
Shell and its client.

The following steps are suggested:

1. Identify available Web Shell technologies (`/api/web-shell`).
2. Identify available features for the desired technology (`/api/web-shell/:technology`).
3. Identify available client technologies (`/api/client`).
4. Craft and send a generation request (`/api/generator`).

#### /web-shell

The `/web-shell` endpoint will return a list of currently supported technologies for the Web Shell executable.
It can be queried by issuing a `GET` request.

Assuming the generator is deployed locally following the instructions above, the following command can be
issued

```bash
curl -s http://localhost:8080/api/web-shell | jq
```

A sample response looks as follows:

```json
[
  {
    "technology": "php",
    "url": "/web-shell/php"
  }
]
```
#### /web-shell/:technology

Consultation of available features for a specific Web Shell technology can be done by querying the `/web-shell/:technology`
endpoint. For instance, the following command can be issued to query all supported features for a PHP-based Web Shell:

```bash
curl -s http://localhost:8080/api/web-shell/php | jq
```

A sample response looks as follows:

```json
[
  {
    "key": "execute-command-no-alternatives",
    "name": "Command Execution",
    "type": "feature",
    "description": "Add command execution support to the generated web shell."
  },
  {
    "key": "ip-validation",
    "name": "IP Validation",
    "type": "security",
    "description": "Restrict inbound connections to the specified IP whitelist.",
    "input": {
      "type": "text",
      "placeholder": "10.128.20.1, 41.310.135.13",
      "label": "Allowed IPs",
      "key": "IP_WHITELIST"
    }
  },
  {
    "key": "php",
    "name": "PHP",
    "type": "output,format",
    "description": "Create a PHP file containing the generated web shell."
  },
  {
    "key": "obfuscate-code",
    "name": "Obfuscate code",
    "type": "output,option",
    "description": "Obfuscate the generated web shell."
  }
]
```

Note that features can be broken into the following categories:

- **feature**: actions that the web shell can perform on the server, such as command execution or
  file upload.
- **security**: additional protections that can be optionally included in the web shell, such as
  replay protection or IP validation
- **output**: available options for customizing the generation result. They can be:
  - **format**: desired format for the generated Web Shell, such as a PHP file or a valid PNG image.
  - **option**: modifiers that can be applied to the generation process, such as code obfuscation.

More information on how to use the returned features for the generation process can be found in the
[generator endpoint](#generator) description.

#### /client

Once the desired information about the Web Shell has been gathered, it is possible to query the available
technologies for the generated client. This can be achieved by sending a `GET` request to the `/client`
endpoint.

```bash
curl -s http://localhost:8080/api/client | jq
```
A sample response looks as follows:

```json
[
  {
    "technology": "python",
    "dependencies": "/dependencies/requirements.txt"
  }
]
```
It will return the available technologies, as well as the endpoint that can be queried to download the
required dependencies.

#### /generator

In order to generate the Web Shell and its client, a generation request must be sent to the `/generator`
endpoint. Such request must use a POST method, and is expected to conform to the following format:

```json
{
  "shell": "<shell-technology>",
  "client": "<client-technology>",
  "features": [
    {
      "key": "<feature-without-arguments-key>"
    },
    {
      "key": "<feature-with-arguments-key>",
      "arguments": [
        {
          "name": "<argument-name>",
          "value": "<argument-value>"
        }
      ]
    }
  ],
  "output": {
    "format": "<output-format>",
    "output-option": true
  }
}
```

The `shell` and `client` options are relatively straightforward, since they are a simple string indicating
the desired target technology. On the other hand, the `feature` and `output` are somewhat more complex.

For the `feature` section, a list of objects is expected by the API. Each entry in the list will correspond
to a feature of either the `feature` or `security` types discussed in the [technology endpoint](#webshelltechnology).

Since the API was designed to interact with the front-end, the previous response cannot be directly used
when manually crafting a request. Each individual feature will be requested as an object with the following keys:

- **`key`** (mandatory): feature to be included. It directly maps to the `key` value returned by the feature request.
- **`arguments`**: some `features` require arguments to be passed to the server. In these cases, a list of objects
  specifying the feature arguments is expected. Each entry will have the following keys:
    - `**name**`: argument name. It corresponds to the value of the `input.key` property returned by the feature request.
    - `**value**`: desired value for the argument. By inspecting the `input.placeholder` property of the required
    request, the expected format can be inferred.

Finally, an `output` object entry is expected to be supplied. This object will be comprised of the following properties:
  - **`format`**: desired output format for the web shell. Its value corresponds to the `key` property of the different
    features of type `output,format` returned by the feature request.
  - **`output-option`** (optional): additional output-processing steps to be performed. More than one output option may
    be optionally supplied. The option's name corresponds to the `key` property of features of type `output,option`
    returned by the feature request.

The following snippets shows an example of a valid generation request:

```bash
curl -s -X POST http://localhost:8080/api/generator          \
          -H 'Content-Type: application/json'                \
          -d '{                                               
                "shell": "php",                               
                "client": "python",                           
                "features": [                                 
                  {                                           
                    "key": "execute-command-alternatives"     
                  },                                          
                  {                                           
                    "key": "ip-validation",                   
                    "arguments": [                            
                      {                                       
                        "name": "IP_WHITELIST",               
                        "value": "127.0.0.1, ::1"             
                      }                                       
                    ]                                         
                  }                                           
                ],                                            
                "output": {                                   
                  "format": "php",                            
                  "obfuscate-code": true                      
                }                                             
              }'                                             \
  | jq
```

The request's response will include the endpoint where the generated files can be downloaded,
as well as their checksum.

```json
{
  "shell": {
    "url": "/output/f2625829d3e3288aa6ee93dd9e5eea861b62ebdcfc12723079d4511ca4c6f695.php",
    "checksum": {
      "algorithm": "SHA256",
      "value": "a42014891d643eab583ef462c79f00c1a14ec89b290cd81c6a90aaca5e77e2e9"
    }
  },
  "client": {
    "url": "/output/c76acb720c4c0c4f85a8ccd0fd8330c769913366b97bbc3fdd15b796ecdc4f87.py",
    "checksum": {
      "algorithm": "SHA256",
      "value": "f26920ccc7399a6d0891f90ae7585f0d29bab406c7a8043b602c15897b5bb28d"
    }
  }
}
```

## Instructions for Developers
