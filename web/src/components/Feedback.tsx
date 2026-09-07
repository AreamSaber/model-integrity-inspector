import { useEffect, useRef } from 'react'
import { ApiError, errorMessage } from '../api'

export function ErrorNotice({ error, id = 'request-error' }: { error: unknown; id?: string }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => { if (error) ref.current?.focus() }, [error])
  if (!error) return null
  return <div className="notice error" role="alert" id={id} tabIndex={-1} ref={ref}>
    <p>{typeof error === 'string' ? error : errorMessage(error)}</p>
    {error instanceof ApiError && error.requestID && <p className="request-id">请求编号：{error.requestID}</p>}
  </div>
}
export function Loading({ children = '正在加载…' }: { children?: string }) {
  return <output className="loading"><span className="status-dot" aria-hidden="true" />{children}</output>
}
