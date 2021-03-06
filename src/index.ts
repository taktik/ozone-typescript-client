import { fsm } from 'typescript-state-machine'
import * as log4javascript from 'log4javascript'
import { httpclient } from 'typescript-http-client'
import { FromOzone, Item, Query, SearchRequest, UUID, State as MetaState, Patch } from 'ozone-type'

export namespace OzoneClient {
	import AssumeStateIsNot = fsm.AssumeStateIsNot
	import Transitions = fsm.Transitions

	import State = fsm.State
	import ListenerRegistration = fsm.ListenerRegistration
	import StateMachine = fsm.StateMachine
	import AssumeStateIs = fsm.AssumeStateIs
	import StateMachineImpl = fsm.StateMachineImpl
	import Filter = httpclient.Filter
	import HttpClient = httpclient.HttpClient
	import Response = httpclient.Response
	import Request = httpclient.Request
	import newHttpClient = httpclient.newHttpClient
	import FilterChain = httpclient.FilterChain
	import InstalledFilter = httpclient.InstalledFilter
	import FilterCollection = httpclient.FilterCollection

	const log = log4javascript.getLogger('ozone.client')
	const DEFAULT_TIMEOUT = 5000

	type Message = any

	export class ClientState extends State {
	}

	export const states = {
		STOPPED: new ClientState('STOPPED'),
		STARTED: new ClientState('STARTED'),
		AUTHENTICATING: new ClientState('AUTHENTICATING'),
		AUTHENTICATED: new ClientState('AUTHENTICATED'),
		NETWORK_OR_SERVER_ERROR: new ClientState('NETWORK_OR_SERVER_ERROR'),
		AUTHENTICATION_ERROR: new ClientState('AUTHENTICATION_ERROR'),
		WS_CONNECTING: new ClientState('WS_CONNECTING'),
		WS_CONNECTED: new ClientState('WS_CONNECTED'),
		WS_CONNECTION_ERROR: new ClientState('WS_CONNECTION_ERROR'),
		STOPPING: new ClientState('STOPPING')
	}

	const validTransitions: Transitions<ClientState> = {}
	validTransitions[states.STOPPED.label] = [states.STARTED]
	validTransitions[states.STARTED.label] = [states.AUTHENTICATING]
	validTransitions[states.AUTHENTICATING.label] = [states.STOPPING, states.AUTHENTICATION_ERROR, states.NETWORK_OR_SERVER_ERROR, states.AUTHENTICATED]
	validTransitions[states.AUTHENTICATED.label] = [states.STOPPING, states.WS_CONNECTING, states.AUTHENTICATING]
	validTransitions[states.AUTHENTICATION_ERROR.label] = [states.STOPPING, states.AUTHENTICATING]
	validTransitions[states.NETWORK_OR_SERVER_ERROR.label] = [states.STOPPING, states.AUTHENTICATING]
	validTransitions[states.WS_CONNECTING.label] = [states.STOPPING, states.WS_CONNECTED, states.WS_CONNECTION_ERROR, states.AUTHENTICATING]
	validTransitions[states.WS_CONNECTED.label] = [states.STOPPING, states.WS_CONNECTION_ERROR, states.AUTHENTICATING]
	validTransitions[states.WS_CONNECTION_ERROR.label] = [states.STOPPING, states.WS_CONNECTING, states.AUTHENTICATING]
	validTransitions[states.STOPPING.label] = [states.STOPPED]

	/*
		digraph G {
			"STOPPED" -> "STARTED"
			"STARTED" -> "AUTHENTICATING"
			"AUTHENTICATING" -> "STOPPING"
			"AUTHENTICATING" -> "AUTHENTICATION_ERROR"
			"AUTHENTICATING" -> "AUTHENTICATED"
			"AUTHENTICATING" -> "NETWORK_OR_SERVER_ERROR"
			"AUTHENTICATION_ERROR" -> "STOPPING"
			"AUTHENTICATION_ERROR" -> "AUTHENTICATING"
			"NETWORK_OR_SERVER_ERROR" -> "STOPPING"
			"NETWORK_OR_SERVER_ERROR" -> "AUTHENTICATING"
			"WS_CONNECTING" -> "STOPPING"
			"WS_CONNECTING" -> "WS_CONNECTED"
			"WS_CONNECTING" -> "WS_CONNECTION_ERROR"
			"WS_CONNECTING" -> "AUTHENTICATING"
			"WS_CONNECTING" -> "NETWORK_OR_SERVER_ERROR"

			"WS_CONNECTED" -> "STOPPING"
			"WS_CONNECTED" -> "WS_CONNECTION_ERROR"
			"WS_CONNECTED" -> "AUTHENTICATING"
			"WS_CONNECTED" -> "NETWORK_OR_SERVER_ERROR"

			"WS_CONNECTION_ERROR" -> "STOPPING"
			"WS_CONNECTION_ERROR" -> "AUTHENTICATING"
			"WS_CONNECTION_ERROR" -> "NETWORK_OR_SERVER_ERROR"
			"WS_CONNECTION_ERROR" -> "WS_CONNECTING"

			"STOPPING" -> "STOPPED"

			"AUTHENTICATED" -> "STOPPING"
			"AUTHENTICATED" -> "AUTHENTICATING"
			"AUTHENTICATED" -> "NETWORK_OR_SERVER_ERROR"
			"AUTHENTICATED" -> "WS_CONNECTING"
		}
	*/

	/*
		Main interface for the Ozone Client
	*/
	export interface OzoneClient extends StateMachine<ClientState> {

		/* Get the client config */
		readonly config: ClientConfiguration

		/* Get the current Authentication if available */
		readonly authInfo?: AuthInfo

		/* Get the last failed login call if any */
		readonly lastFailedLogin?: Response<AuthInfo>

		/*
			Convenience props for getting the status of the client.
		*/
		readonly isAuthenticated: boolean
		readonly isConnected: boolean

		/*
			Start the client. To be called once
		*/
		start(): Promise<void>

		/*
			The array of filters to apply to all HTTP calls
			BEFORE this OzoneClient's own internal filters.
			This array can be modified at any time to add/remove filters
		 */
		readonly preFilters: InstalledFilter[]

		/*
			The array of filters to apply to all HTTP calls
			AFTER this OzoneClient's own internal filters.
			This array can be modified at any time to add/remove filters
		 */
		readonly postFilters: InstalledFilter[]

		/*
			Update the WS URL.
			The client will attempt to connect automatically to the new URL.
		*/
		updateWSURL(url: string): void

		/*
			Update the Ozone credentials.
			The client will attempt to login automatically.
		*/
		updateCredentials(ozoneCredentials: OzoneCredentials): void

		/*
			Stop the client. To be called once
		*/
		stop(): Promise<void>

		/*
			Perform a low-level call
			All calls towards Ozone or other Microservices secured by Ozone should use those calls
		*/
		callForResponse<T>(request: Request): Promise<Response<T>>

		call<T>(request: Request): Promise<T>

		/*
			Register a message listener.

			@param messageType The type of message to register for
			@param callBack The callBack that will be called
		*/
		onMessage<M extends Message>(messageType: string, callBack: (message: M) => void): ListenerRegistration

		onAnyMessage(callBack: (message: Message) => void): ListenerRegistration

		/*
			Send a message
		*/
		send(message: Message): void

		// BEGIN HIGH LEVEL CALLS

		/*
			Get a client for working with items of the given type
		*/
		itemClient<T extends Item>(typeIdentifier: string): ItemClient<T>

		/*
			Insert the current Ozone session ID in the given URL ("/dsid=...).
			This call
			Throws an error if there is no session available.
			The given string may or may not contain the host part.
			Example input strings :
			"/rest/v3/blob"
			"https://taktik.io/rest/v2/media/view/org.taktik.filetype.original/123"
		*/
		insertSessionIdInURL(url: string): string
	}

	export interface SearchResults<T extends Item> {
		id?: number

		total?: number

		size?: number

		results?: T[]

	}

	export interface ItemClient<T extends Item> {
		save(item: Patch<T>): Promise<FromOzone<T>>

		saveAll(items: Patch<T>[]): Promise<FromOzone<T>[]>

		findOne(id: UUID): Promise<FromOzone<T> | null>

		findAll(): Promise<FromOzone<T>[]>

		findAllByIds(ids: UUID[]): Promise<FromOzone<T>[]>

		search(searchRequest: SearchRequest): Promise<SearchResults<FromOzone<T>>>

		count(query?: Query): Promise<number>

		deleteById(id: UUID, permanent?: boolean): Promise<UUID | null>

		deleteByIds(ids: UUID[], permanent?: boolean): Promise<UUID[]>
	}

	interface OzoneClientInternals extends OzoneClient {
		/* Allow state change */
		setState(newState: ClientState): void

	}

	const MAX_REAUTH_DELAY: number = 30000
	const INITIAL_REAUTH_DELAY: number = 1000

	const MAX_WS_RECONNECT_DELAY: number = 30000
	const INITIAL_WS_RECONNECT_DELAY: number = 1000

	const MAX_SESSION_CHECK_DELAY: number = 60000

	export interface AuthInfo {
		principalClass: string,
		principalId: string,
		sessionId: string,
	}

	class Listener {
		active: boolean = true
	}

	class MessageListener extends Listener {
		constructor(
			readonly callBack: (message: Message) => void,
			readonly messageType?: string
		) {
			super()
		}
	}

	interface MessageListeners {
		[messageType: string]: MessageListener[]
	}

	/*
		Factory method
	*/
	export function newOzoneClient(config: ClientConfiguration) {
		return new OzoneClientImpl(config)
	}

	class OzoneClientImpl extends StateMachineImpl<ClientState> implements OzoneClientInternals {
		private readonly _config: ClientConfiguration
		private _authInfo?: AuthInfo
		private _ws?: WebSocket
		private _lastFailedLogin?: Response<AuthInfo>
		private readonly _messageListeners: MessageListeners
		private _lastSessionCheck: number = 0
		private _httpClient: HttpClient
		readonly preFilters: InstalledFilter[] = []
		readonly postFilters: InstalledFilter[] = []

		constructor(configuration: ClientConfiguration) {
			super(Object.values(states), validTransitions, states.STOPPED)
			this._config = configuration
			this._messageListeners = {}
			this.setupTransitionListeners()
			this._httpClient = newHttpClient()
			// Setup client & filters
			this.setupFilters()
		}

		get config(): ClientConfiguration {
			return this._config
		}

		get authInfo(): AuthInfo | undefined {
			return this._authInfo
		}

		get lastFailedLogin(): Response<AuthInfo> | undefined {
			return this._lastFailedLogin
		}

		get isAuthenticated(): boolean {
			return this.inOneOfStates([states.WS_CONNECTED, states.WS_CONNECTING, states.WS_CONNECTION_ERROR, states.AUTHENTICATED])
		}

		get isConnected(): boolean {
			return this.inState(states.WS_CONNECTED)
		}

		onMessage<M extends Message>(messageType: string, callBack: (message: M) => void): ListenerRegistration {
			return this.addMessageListener(message => callBack(message as M), messageType)
		}

		onAnyMessage(callBack: (message: any) => void): ListenerRegistration {
			return this.addMessageListener(callBack, undefined)
		}

		send(message: Message): void {
			this.checkInState(states.WS_CONNECTED, 'Cannot send message : Not connected')
			this._ws!.send(JSON.stringify(message))
		}

		async start(): Promise<void> {
			this.checkInState(states.STOPPED, 'Client already started')
			this.setState(states.STARTED)
			if (this.config.ozoneCredentials) {
				await this.waitUntilEnteredOneOf([states.AUTHENTICATION_ERROR, states.AUTHENTICATED, states.NETWORK_OR_SERVER_ERROR])
			}
		}

		updateWSURL(url: string): void {
			if (this._config.webSocketsURL !== url) {
				this._config.webSocketsURL = url
				// If we are authenticated but not connected to WS, try to connect
				if (this.canGoToState(states.WS_CONNECTING)) {
					this.connectIfPossible()
				} else if (this.inOneOfStates([states.WS_CONNECTED, states.WS_CONNECTING])) {
					OzoneClientImpl.terminateWSConnectionForcefully(this._ws!)
				}
			}
		}

		updateCredentials(credentials: OzoneCredentials): void {
			this._config.ozoneCredentials = credentials
			if (this.canGoToState(states.AUTHENTICATING)) {
				this.loginIfPossible()
			} else if (this.inOneOfStates([states.WS_CONNECTED, states.WS_CONNECTING])) {
				OzoneClientImpl.terminateWSConnectionForcefully(this._ws!)
			}
		}

		// TODO AB Implement
		stop(): Promise<void> {
			return Promise.reject('Not implemented')
		}

		async call<T>(call: Request): Promise<T> {
			return this._httpClient.call<T>(call)
		}

		async callForResponse<T>(call: Request): Promise<Response<T>> {
			return this._httpClient.callForResponse<T>(call)
		}

		private onWsMessage(message: MessageEvent) {
			if (message.data === 'ping') {
				this._ws && this._ws.send('pong')
			} else if (message.data === 'pong') {
				this.handlePong()
			} else {
				const parsedJSONMessage = OzoneClientImpl.parseMessage(message)
				if (parsedJSONMessage) {
					this.dispatchMessage(parsedJSONMessage)
				}
			}
		}

		private static parseMessage(message: MessageEvent): Message | null {
			try {
				return JSON.parse(message.data) as Message
			} catch (e) {
				log.error('Unable to parse websocket message:', message, '// Error:', e)
				return null
			}
		}

		@AssumeStateIs(states.WS_CONNECTED)
		private handlePong() {
			this._lastReceivedPong = Date.now()
		}

		// Attempt a single Ozone login
		@AssumeStateIs(states.AUTHENTICATING)
		private async login() {
			// Destroy any existing WS
			this.destroyWs()
			try {
				this._authInfo = undefined
				this.log.debug('Authenticating')
				this.log.debug(`this.config.ozoneURL ${this.config.ozoneURL}`)
				this._authInfo = await this.config.ozoneCredentials!.authenticate(this.config.ozoneURL)
				this.log.debug(`Authenticated with authInfo : ${JSON.stringify(this._authInfo)}`)
				this._lastFailedLogin = undefined
				this._lastSessionCheck = Date.now()
				this.setState(states.AUTHENTICATED)
			} catch (e) {
				// TODO AB What if e is not a Response?
				const response = e as Response<AuthInfo>
				this.log.debug(`Authentication error : code ${response.status}`)
				this._lastFailedLogin = e
				if (response.status >= 400 && response.status < 500) {
					// Invalid credentials
					this.setState(states.AUTHENTICATION_ERROR)
				} else {
					this.setState(states.NETWORK_OR_SERVER_ERROR)
				}
			}
		}

		private static terminateWSConnectionForcefully(ws: WebSocket) {
			ws.close(4000)
			// Call onError explicitly, because close() doesn't call onClose immediately
			ws.onerror!(new Event('ForceClose'))
		}

		private destroyWs() {
			if (this._ws) {
				let socket = this._ws
				this._ws = undefined
				try {
					if (socket.readyState === socket.CONNECTING || socket.readyState === socket.OPEN) {
						socket.close(4000)
					}
				} catch (e) {
					// TODO AB DO something with e ?
				}
			}
		}

		// Attempt a single WebSocket connect
		@AssumeStateIs(states.WS_CONNECTING)
		connect(): Promise<void> {
			// Destroy any existing WS
			this.destroyWs()
			log.info(`Connecting to ${this._config.webSocketsURL}`)
			return new Promise<void>((resolve, reject) => {
				/* FIXME AB Something is wrong here. The promise resolve or reject method should always be called but it is not the case */
				const query = '?ozoneSessionId=' + this.authInfo!.sessionId
				const ws = new WebSocket(this._config.webSocketsURL + query)
				this._ws = ws
				ws.onerror = ev => {
					if (this._ws === ws) {
						let mustReject = this._state === states.WS_CONNECTING
						try {
							if (this.state !== states.WS_CONNECTION_ERROR) {
								// Destroy the WS
								this.destroyWs()
								this.setState(states.WS_CONNECTION_ERROR)
							}
						} finally {
							if (mustReject) {
								reject(ev)
							}
						}
					}
				}
				ws.onclose = ev => {
					if (this._ws === ws) {
						let mustReject = this._state === states.WS_CONNECTING
						try {
							if (this.state !== states.WS_CONNECTION_ERROR) {
								// Destroy the WS
								this.destroyWs()
								if (ev.code === 4001) {
									this.setState(states.AUTHENTICATING)
								} else {
									this.setState(states.WS_CONNECTION_ERROR)
								}
							}
						} finally {
							if (mustReject) {
								reject(ev)
							}
						}
					}
				}
				ws.onopen = () => {
					let mustResolve = this._state === states.WS_CONNECTING
					try {
						log.info(`Connected to ${this._config.webSocketsURL}`)
						this.setState(states.WS_CONNECTED)
					} catch (e) {
						mustResolve = false
						reject(e)
					}
					if (mustResolve) {
						resolve()
					}
				}
				ws.onmessage = (msg) => {
					if (this._ws === ws) {
						this.onWsMessage(msg)
					}
				}
			})
		}

		/*
			Login if we have credentials
		*/
		private loginIfPossible() {
			if (this._config.ozoneCredentials) {
				this.setState(states.AUTHENTICATING)
			}
		}

		/*
			Connect if we have an URL, ignore errors
		*/
		private connectIfPossible() {
			if (this._config.webSocketsURL) {
				this.setState(states.WS_CONNECTING)
			}
		}

		private addMessageListener(callBack: (message: Message) => void, messageType?: string) {
			const messageTypeLabel = messageType || '*'
			if (!this._messageListeners[messageTypeLabel]) {
				this._messageListeners[messageTypeLabel] = []
			}
			const listenersForMessageType = this._messageListeners[messageTypeLabel]
			const messageListener = new MessageListener(callBack, messageType)
			listenersForMessageType.push(messageListener)
			return {
				cancel(): void {
					messageListener.active = false
				}
			}
		}

		// Auto Re-auth to Ozone

		private _lastReAuth: number = 0
		private _lastReAuthInterval: number = 0
		private _reAuthTimeout: number = 0

		// Exponential back-off
		private nextReAuthRetryInterval(): number {
			if (this._lastReAuth === 0) {
				return INITIAL_REAUTH_DELAY
			} else if (this._lastReAuthInterval === 0) {
				return Math.min(2 * INITIAL_REAUTH_DELAY, MAX_REAUTH_DELAY)
			}
			return Math.min(2 * this._lastReAuthInterval, MAX_REAUTH_DELAY)
		}

		@AssumeStateIs(states.NETWORK_OR_SERVER_ERROR)
		private createAutoReAuthTimer() {
			this._reAuthTimeout = window.setTimeout(() =>
				(async () => {
					try {
						if (this.canGoToState(states.AUTHENTICATING)) {
							const now = Date.now()
							if (this._lastReAuth !== 0) {
								this._lastReAuthInterval = now - this._lastReAuth
							}
							this._lastReAuth = now
							this.setState(states.AUTHENTICATING)
						}
					} catch (e) {
						log.info('login failed : ' + e)
					}
				})(), this.nextReAuthRetryInterval())
		}

		@AssumeStateIsNot(states.NETWORK_OR_SERVER_ERROR)
		private clearAutoReAuthTimer() {
			window.clearTimeout(this._reAuthTimeout)
			this._reAuthTimeout = 0
		}

		private clearAutoReAuthRetryTimestamps() {
			this._lastReAuth = 0
			this._lastReAuthInterval = 0
		}

		// WS KeepAlive

		private _wsKeepAliveTimer?: number
		private _lastReceivedPong: number = 0
		private _lastSentPing: number = 0

		private installWSPingKeepAlive() {
			if (this._wsKeepAliveTimer) {
				// should not happen
				log.warn('wsKeepAliveTimer defined when it should not be')
				clearTimeout(this._wsKeepAliveTimer)
			}
			this._lastReceivedPong = Date.now()
			this._wsKeepAliveTimer = window.setInterval(() => this.wsKeepAlive(), 10000)
		}

		private destroyWSPingKeepAlive() {
			this._lastSentPing = 0
			this._lastReceivedPong = 0
			if (this._wsKeepAliveTimer) {
				clearTimeout(this._wsKeepAliveTimer)
				this._wsKeepAliveTimer = undefined
			}
		}

		@AssumeStateIs(states.WS_CONNECTED)
		private wsKeepAlive() {
			if (!this._ws) {
				return
			}
			// We have at least sent one ping and no pong received for more than 30s since last ping
			// --> Problem. We close the socket and trigger onClose()
			if (this._lastSentPing !== 0 && (this._lastSentPing - this._lastReceivedPong) > 20000) {
				if (this._ws.readyState === this._ws.CONNECTING || this._ws.readyState === this._ws.OPEN) {
					log.warn('Ping timeout, closing connection')
					OzoneClientImpl.terminateWSConnectionForcefully(this._ws)
				}
			} else {
				const now = Date.now()
				this._lastSentPing = now
				let message: string = 'ping'
				if (now - this._lastSessionCheck > MAX_SESSION_CHECK_DELAY) {
					this._lastSessionCheck = now
					/*
												It has been a while since we last checked the session validity,
												so ask the WS server to check it. The server will close the connection
												if the session is expired
										 */
					message += '!'
				}
				this._ws.send(message)
			}
		}

		// WS Auto-reconnect

		private _lastWSReconnect: number = 0
		private _lastWSReconnectInterval: number = 0
		private _wsReconnectTimeout: number = 0

		// Exponential back-off
		private nextWSRetryInterval(): number {
			if (this._lastWSReconnect === 0) {
				return INITIAL_WS_RECONNECT_DELAY
			} else if (this._lastWSReconnectInterval === 0) {
				return Math.min(2 * INITIAL_WS_RECONNECT_DELAY, MAX_WS_RECONNECT_DELAY)
			}
			return Math.min(2 * this._lastWSReconnectInterval, MAX_WS_RECONNECT_DELAY)
		}

		@AssumeStateIs(states.WS_CONNECTION_ERROR)
		private createAutoReconnectWSTimer() {
			const nextWSRetryInterval = this.nextWSRetryInterval()
			this._wsReconnectTimeout = window.setTimeout(() => (async () => {
				if (this.canGoToState(states.WS_CONNECTING)) {
					const now = Date.now()
					if (this._lastWSReconnect !== 0) {
						this._lastWSReconnectInterval = now - this._lastWSReconnect
					}
					this._lastWSReconnect = now
					this.setState(states.WS_CONNECTING)
				}
			})(), nextWSRetryInterval)

		}

		@AssumeStateIsNot(states.WS_CONNECTION_ERROR)
		private clearAutoReconnectWSTimer() {
			window.clearTimeout(this._wsReconnectTimeout)
			this._wsReconnectTimeout = 0
		}

		private _clearWSRetryTimestampsTimeout: number = 0

		@AssumeStateIs(states.WS_CONNECTED)
		private scheduleClearAutoReconnectWSRetryTimestamps() {
			this._clearWSRetryTimestampsTimeout = window.setTimeout(() => {
				this._lastWSReconnect = 0
				this._lastWSReconnectInterval = 0
			}, 30000)
		}

		@AssumeStateIsNot(states.WS_CONNECTED)
		private cancelClearAutoReconnectWSRetryTimestamps() {
			window.clearTimeout(this._clearWSRetryTimestampsTimeout)
			this._clearWSRetryTimestampsTimeout = 0
		}

		private static invokeMessageListeners(message: Message, listeners?: MessageListener[]) {
			if (listeners) {
				for (let index = 0; index < listeners.length; index++) {
					let listener = listeners[index]
					if (listener.active) {
						try {
							listener.callBack(message)
						} catch (e) {
							log.warn('Uncaught error in message listener :' + e)
						}
					} else {
						// Remove inactive listener
						listeners.splice(index, 1)
						index--
					}
				}
			}
		}

		private dispatchMessage(message: Message) {
			OzoneClientImpl.invokeMessageListeners(message, this._messageListeners[message.type])
			OzoneClientImpl.invokeMessageListeners(message, this._messageListeners['*'])
		}

		private setupTransitionListeners() {
			// Initiate login when started if possible
			this.onEnterState(states.STARTED, () => this.loginIfPossible())
			// Perform login when entering state "AUTHENTICATING"
			this.onEnterState(states.AUTHENTICATING, () => this.login())
			// Auto re-authenticate to Ozone in case of error
			this.onEnterState(states.NETWORK_OR_SERVER_ERROR, () => this.createAutoReAuthTimer())
			this.onLeaveState(states.NETWORK_OR_SERVER_ERROR, () => this.clearAutoReAuthTimer())
			this.onEnterState(states.AUTHENTICATED, () => this.clearAutoReAuthRetryTimestamps())
			this.onEnterState(states.AUTHENTICATION_ERROR, () => this.clearAutoReAuthRetryTimestamps())
			// Auto-connect WebSocket when authenticated to Ozone
			this.onEnterState(states.AUTHENTICATED, () => this.connectIfPossible())
			// Connect to message server when entering state "CONNECTING"
			this.onEnterState(states.WS_CONNECTING, () => this.connect())
			// WS Ping KeepAlive
			this.onEnterState(states.WS_CONNECTED, () => this.installWSPingKeepAlive())
			this.onLeaveState(states.WS_CONNECTED, () => this.destroyWSPingKeepAlive())
			// Auto-reconnect WS in case of error
			this.onEnterState(states.WS_CONNECTION_ERROR, () => this.createAutoReconnectWSTimer())
			this.onLeaveState(states.WS_CONNECTION_ERROR, () => this.clearAutoReconnectWSTimer())
			this.onEnterState(states.WS_CONNECTED, () => this.scheduleClearAutoReconnectWSRetryTimestamps())
			this.onLeaveState(states.WS_CONNECTED, () => this.cancelClearAutoReconnectWSRetryTimestamps())
		}

		private setupFilters() {
			// Add pre-filters
			this._httpClient.addFilter(new FilterCollection(this.preFilters), 'pre-filters')
			// Try to auto-refresh the session if expired
			this._httpClient.addFilter(new SessionRefreshFilter(this, lastCheck => this._lastSessionCheck = lastCheck), 'session-refresh')
			// Add Ozone session header to all requests
			this._httpClient.addFilter(new SessionFilter(() => this._authInfo), 'session-filter')
			// Set some sensible default to all requests
			this._httpClient.addFilter(new DefaultsOptions(this._config.defaultTimeout || DEFAULT_TIMEOUT), 'default-options')
			// Add post-filters
			this._httpClient.addFilter(new FilterCollection(this.postFilters), 'post-filters')
		}

		itemClient<T extends Item>(typeIdentifier: string): ItemClient<T> {
			const client = this
			const baseURL = this._config.ozoneURL
			return new class implements ItemClient<T> {
				async count(query?: Query): Promise<number> {
					const results = await this.search({
						query: query,
						size: 0
					})
					return results.total || 0
				}

				deleteById(id: UUID, permanent?: boolean): Promise<UUID | null> {
					const request = new Request(`${baseURL}/rest/v3/items/${typeIdentifier}/${id}`)
						.setMethod('DELETE')
					return client.call<UUID>(request)
				}

				deleteByIds(ids: UUID[], permanent?: boolean): Promise<UUID[]> {
					const request = new Request(`${baseURL}/rest/v3/items/${typeIdentifier}/bulkDelete`)
						.setMethod('POST')
						.setBody()
					return client.call<UUID[]>(request)
				}

				async findAll(): Promise<FromOzone<T>[]> {
					const results = await this.search({
						size: 10_000
					})
					return results.results || []
				}

				findAllByIds(ids: UUID[]): Promise<FromOzone<T>[]> {
					const request = new Request(`${baseURL}/rest/v3/items/${typeIdentifier}/bulkGet`)
						.setMethod('POST')
						.setBody(ids)
					return client.call<FromOzone<T>[]>(request)
				}

				findOne(id: UUID): Promise<FromOzone<T> | null> {
					const request = new Request(`${baseURL}/rest/v3/items/${typeIdentifier}/${id}`)
						.setMethod('GET')
					return client.call<FromOzone<T>>(request)
				}

				async save(item: Patch<T>): Promise<FromOzone<T>> {
					const request = new Request(`${baseURL}/rest/v3/items/${typeIdentifier}`)
						.setMethod('POST')
						.setBody(item)
					const savedItem = await client.call<FromOzone<T>>(request)
					if (savedItem._meta.state === MetaState.ERROR) {
						throw savedItem
					}
					return savedItem
				}

				async saveAll(items: Patch<T>[]): Promise<FromOzone<T>[]> {
					const request = new Request(`${baseURL}/rest/v3/items/${typeIdentifier}/bulkSave`)
						.setMethod('POST')
						.setBody(items)
					const savedItems = await client.call<FromOzone<T>[]>(request)
					if (savedItems.some(item => item._meta.state === MetaState.ERROR)) {
						throw savedItems
					}
					return savedItems
				}

				search(searchRequest: SearchRequest): Promise<SearchResults<FromOzone<T>>> {
					const request = new Request(`${baseURL}/rest/v3/items/${typeIdentifier}/search`)
						.setMethod('POST')
						.setBody(searchRequest)
					return client.call<SearchResults<FromOzone<T>>>(request)
				}
			}()
		}

		insertSessionIdInURL(url: string): string {
			if (!url.startsWith(this.config.ozoneURL)) {
				throw new Error(`insertSessionIdInURL : Given url should start with base url ${this.config.ozoneURL}`)
			}
			if (!this.authInfo) {
				throw new Error(`insertSessionIdInURL : There is no valid session`)
			}
			return `${this.config.ozoneURL}/dsid=${this.authInfo.sessionId}${url.substring(this.config.ozoneURL.length)}`
		}

	}

	function addHeader(call: Request, name: string, value: string) {
		if (!call.headers) {
			call.headers = {}
		}
		call.headers[name] = value
	}

	export abstract class OzoneCredentials {
		abstract authenticate(ozoneURL: string): Promise<AuthInfo>
	}

	export class UserCredentials extends OzoneCredentials {
		constructor(readonly username: string,
					readonly password: string) {
			super()
		}

		authenticate(ozoneURL: string): Promise<AuthInfo> {
			const httpClient = newHttpClient()
			const request = new Request(`${ozoneURL}/rest/v3/authentication/login/user`)
				.set({
					method: 'POST',
					body: {
						'username': this.username,
						'password': this.password
					}
				})
			return (httpClient.call<AuthInfo>(request))
		}
	}

	export class TokenCredentials extends OzoneCredentials {
		constructor(readonly token: string) {
			super()
		}

		authenticate(ozoneURL: string): Promise<AuthInfo> {
			return Promise.reject('Not implemented')
		}
	}

	export class ItemCredentials extends OzoneCredentials {
		constructor(readonly itemId: string,
					readonly secret: string) {
			super()
		}

		authenticate(ozoneURL: string): Promise<AuthInfo> {
			return Promise.reject('Not implemented')
		}
	}

	export class SessionCredentials extends OzoneCredentials {
		async authenticate(ozoneURL: string): Promise<AuthInfo> {
			const httpClient = newHttpClient()
			const request = new Request(`${ozoneURL}/rest/v3/authentication/current/session`)
				.set({
					method: 'GET',
					withCredentials: true
				})
			let authInfo = await (httpClient.call<AuthInfo>(request))
			if (!authInfo) {
				// The session is invalid
				throw new Response<AuthInfo>(request, 403, 'Invalid session', {}, authInfo)
			}
			return authInfo
		}
	}

	export class ItemByQueryCredentials extends OzoneCredentials {

		constructor(readonly typeIdentifier: string,
					readonly secret: string,
					readonly query: object) {
			super()
		}

		async authenticate(ozoneURL: string): Promise<AuthInfo> {
			const httpClient = newHttpClient()
			const request = new Request(`${ozoneURL}/rest/v3/authentication/login/item/${this.typeIdentifier}`)
				.set({
					method: 'POST',
					body: {
						query: this.query,
						secret: this.secret
					}
				})
			return (httpClient.call<AuthInfo>(request))
		}
	}

	export interface ClientConfiguration {
		ozoneURL: string
		ozoneInstanceId?: string
		ozoneCredentials?: OzoneCredentials
		webSocketsURL?: string
		defaultTimeout?: number
	}

	/*
		Try to transparently re-authenticate and retry the call if we received a 403 or 401.
		Also, update the last session check
	*/
	class SessionRefreshFilter implements Filter {
		constructor(readonly client: OzoneClientInternals, readonly sessionCheckCallBack: (lastCheck: number) => void) {}

		async doFilter(call: Request, filterChain: FilterChain): Promise<Response<any>> {
			try {
				const response = await filterChain.doFilter(call)
				const principalId = response.headers['ozone-principal-id']
				if (principalId && this.client.authInfo && principalId === this.client.authInfo.principalId) {
					this.sessionCheckCallBack(Date.now())
				}
				return response
			} catch (e) {
				const response = e as Response<any>
				// Try to detect if the session needs to be refreshed
				if (
					// Only try to re-authenticate if we receive a 401 or 403 status code
					(response.status === 403 || response.status === 401)
					// If we receive a principal id, it means we are still authenticated with a valid session, so there is no need
					// to try to re-authenticate
					&& !response.headers['ozone-principal-id']
					// Only try to re-authenticate if we are already authenticated
					&& this.client.isAuthenticated) {
					try {
						// TODO AB Protect this call to avoid multiple login in //
						// TODO AB Destroy WebSocket ( don't wait connecting state)
						// This will trigger a login
						this.client.setState(states.AUTHENTICATING)
						// await result of login
						await this.client.waitUntilLeft(states.AUTHENTICATING)
						// Retry the call
						return await filterChain.doFilter(call)
					} catch (e) {
						// TODO AB Maybe : set state to authentication error in case of login error?
						throw e
					}
				} else {
					throw e
				}
			}
		}
	}

	/*
		Add "Ozone-Session-Id" Header
	*/
	class SessionFilter implements Filter {
		constructor(readonly authProvider: () => AuthInfo | undefined) {}

		async doFilter(call: Request, filterChain: FilterChain): Promise<Response<any>> {
			const authInfo = this.authProvider()
			if (authInfo) {
				addHeader(call, 'Ozone-Session-Id', authInfo.sessionId)
			}
			return filterChain.doFilter(call)
		}
	}

	/*
		Add sensible defaults to requests
	*/
	class DefaultsOptions implements Filter {
		private readonly defaultTimeout: number

		constructor(defaultTimeout: number) {
			this.defaultTimeout = defaultTimeout
		}

		async doFilter(request: Request, filterChain: FilterChain): Promise<Response<any>> {
			if (!request.timeout || request.timeout > this.defaultTimeout) {
				request.timeout = this.defaultTimeout
			}
			return filterChain.doFilter(request)
		}
	}

}
