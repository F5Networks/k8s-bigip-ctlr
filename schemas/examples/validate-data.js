/*-
 * Copyright (c) 2016-2018, F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

const https = require('https');
const fs = require('fs');
const Validator = require('jsonschema').Validator;
const program = require('commander');

let v = new Validator();
let baseUri;

let testing = false;

program.version('0.1.0')
  .option('-t, --testing', 'Testing environment / use local file system')
  .option('-b, --baseuri [uri]', 'Base URI to be used for schema resolution')
  .parse(process.argv);

if (program.baseuri) {
  baseUri = program.baseuri;
} else {
  baseUri =
    "https://bldr-git.int.lineratesystems.com/velcro" +
    "/schemas/raw/master/examples";
}

if (program.testing) {
  baseUri = process.cwd();
  testing = true;
}

if (!baseUri.endsWith('/')) {
  baseUri = baseUri + '/';
}

const initSchemaUri = baseUri + "schemas/enforce-VirtualServer-types_v0.1.0.json";

const data = {
  "positive-integer-field": 1,
  "non-empty-string-field": "this string has stuff",
  "negative-integer-field": "expect error"
};

let idFixup = (baseUri, schema) => {
  return schema.replace(/f5schemadb:\/\//g, baseUri);
}

let getUri = (uri, cb) => {
  https.get(uri, resp => {
    let data = [];

    resp.on('data', chunk => {
      data.push(chunk);
    }).on('end', () => {
      let s = idFixup(baseUri, Buffer.concat(data).toString('ascii'));
      cb(s);
    });
  });
};

let loadFile = (uri, cb) => {
  let index = uri.indexOf('#');
  let _uri = (index === -1) ? uri : uri.substring(0, index);

  let readStream = fs.createReadStream(_uri, {flags: 'r'});

  let data = [];

  readStream.on('data', chunk => {
    data.push(chunk);
  }).on('end', () => {
    let s = idFixup(baseUri, Buffer.concat(data).toString('ascii'));
    cb(s);
  });
};

let resolveSchemas = (v, initSchema, resolverCb, doneCb) => {
  let recvCb = schema => {
    if (schema) {
      v.addSchema(JSON.parse(schema));
    }
    let nextSchema = v.unresolvedRefs.shift();
    if (!nextSchema) {
      doneCb();
      return;
    }
    resolverCb(nextSchema, recvCb);
  };
  resolverCb(initSchema, recvCb);
};

resolveSchemas(v, initSchemaUri, testing ? loadFile : getUri, () => {
  console.log(v.validate(data, v.getSchema(initSchemaUri)));
});
