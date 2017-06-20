/*-
 * Copyright 2016 F5 Networks Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

/* nodeunit PR #244: Uncaught exceptions are silenced.
 * Call handleError function at the beginning of tests to catch exceptions
 * thrown from the test
 `*/
let doHandle = err => {
    throw err;
};
let handleError = () => {
    if (process.listeners('uncaughtException').indexOf(doHandle) === -1) {
          process.on('uncaughtException', doHandle);
            }
};

const SchemaHandler = require('./schema-handler.js').SchemaHandler;

module.exports = {
    handleError: handleError,
    SchemaHandler: SchemaHandler
};
