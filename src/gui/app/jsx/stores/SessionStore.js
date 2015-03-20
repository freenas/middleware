// Session Flux Store
// ==================
// Stores the user's credentials for GUI use. Not the source of truth.

"use strict";

var _            = require("lodash");
var EventEmitter = require("events").EventEmitter;

var FreeNASDispatcher = require("../dispatcher/FreeNASDispatcher");
var FreeNASConstants  = require("../constants/FreeNASConstants");

// Middleware
var MiddlewareClient = require("../middleware/MiddlewareClient");


var ActionTypes  = FreeNASConstants.ActionTypes;
var CHANGE_EVENT ="change";

var _currentUser = "";
var _loggedIn = false;


var SessionStore = _.assign( {}, EventEmitter.prototype, {

    emitChange: function() {
      this.emit( CHANGE_EVENT );
    }

  , addChangeListener: function( callback ) {
      this.on( CHANGE_EVENT, callback );
    }

  , removeChangeListener: function( callback ) {
      this.removeListener( CHANGE_EVENT, callback );
    }

  , getCurrentUser: function () {
      return _currentUser;
  }

  , getLoginStatus: function () {
      return _loggedIn;
  }

});

SessionStore.dispatchToken = FreeNASDispatcher.register( function( payload ) {
  var action = payload.action;

  switch ( action.type ) {

    case ActionTypes.UPDATE_AUTH_STATE:
      _currentUser = action.currentUser;
      _loggedIn = action.loggedIn;
      SessionStore.emitChange();
      break;

    default:
      //No action


  }

});

module.exports = SessionStore;
