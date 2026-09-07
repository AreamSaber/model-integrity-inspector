import { ApiError } from '../../api'
import { runMessages } from '../../runs-api'
import { ErrorNotice } from '../Feedback'

export function RunError({ error, id = 'run-error' }: { error: unknown; id?: string }) {
  const known = error instanceof ApiError ? runMessages[error.code] : undefined
  return <><ErrorNotice error={known ?? error} id={id} />{known && error instanceof ApiError && error.requestID && <p className="request-id">请求编号：{error.requestID}</p>}</>
}
