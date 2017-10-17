/*-
 * Copyright 2016 F5 Networks Inc.
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

const fs = require('fs');
const Validator = require('jsonschema').Validator;
const ValidatorHelpers = require('jsonschema/lib/helpers');


Validator.prototype.customFormats.bigipv4 = function(input) {
   let parts = input.split("%");
   let ip = parts[0];
   if (parts.length === 2) {
     let rd = parts[1];
     if (isNaN(rd)) {
       return false;
     }
   }

   return ValidatorHelpers.isFormat(ip, 'ip-address');
}

Validator.prototype.customFormats.bigipv6 = function(input) {
   let parts = input.split("%");
   let ip = parts[0];
   if (parts.length === 2) {
     let rd = parts[1];
     if (isNaN(rd)) {
       return false;
     }
   }
   return ValidatorHelpers.isFormat(ip, 'ipv6');
}


class SchemaHandler {
  constructor(uriRoot) {
    this._parentUri;
    this._uriRoot = uriRoot;
    if (!this._uriRoot.endsWith('/')) {
      this._uriRoot = this._uriRoot + '/';
    }

    this._v = new Validator();
  }

  _uriFixup(schema) {
    let _tmp = schema.replace(/f5schemadb:\/\//g, this._uriRoot);
    return fs.realpathSync(_tmp);
  }

  _loadFile(uri, cb) {
    let index = uri.indexOf('#');
    let _uri = (index === -1) ? uri : uri.substring(0, index);

    let readStream = fs.createReadStream(_uri, { flags: 'r' });

    let data = [];

    readStream.on('data', chunk => {
      data.push(chunk);
    }).on('end', () => {
      let schemaObj = JSON.parse(Buffer.concat(data).toString('ascii'));
      cb(schemaObj);
    });
  }

  loadSchemas(schemaUri, doneCb) {
    this._parentUri = this._uriFixup(schemaUri);
    let loadedCb = schema => {
      if (schema) {
        if (schema.id) {
          schema.id = this._uriFixup(schema.id);
          this._v.addSchema(schema);
        }
      }
      let nextSchema = this._v.unresolvedRefs.shift();
      if (!nextSchema) {
        doneCb();
        return;
      }
      this._loadFile(nextSchema, loadedCb);
    };
    this._loadFile(this._parentUri, loadedCb);
  }

  runValidate(dataObj) {
    return this._v.validate(dataObj, this._v.getSchema(this._parentUri));
  }
}

module.exports.SchemaHandler = SchemaHandler;
