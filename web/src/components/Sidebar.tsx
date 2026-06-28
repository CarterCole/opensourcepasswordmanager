import { useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  Key,
  Fingerprint,
  RefreshCw,
  ScrollText,
  Settings,
  ChevronRight,
  ChevronDown,
  FolderOpen,
  Folder,
  FileKey,
  Lock,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { listMounts, listSecrets } from '../api/client'

const NAV_ITEMS = [
  { to: '/secrets', icon: Key, label: 'Secrets' },
  { to: '/api-keys', icon: Fingerprint, label: 'API Keys' },
  { to: '/sync', icon: RefreshCw, label: 'Sync' },
  { to: '/audit', icon: ScrollText, label: 'Audit Log' },
]

interface TreeNodeProps {
  mount: string
  path: string
  label: string
  depth?: number
}

function TreeNode({ mount, path, label, depth = 0 }: TreeNodeProps) {
  const [open, setOpen] = useState(false)
  const isFolder = label.endsWith('/')
  const navigate = useNavigate()

  const { data } = useQuery({
    queryKey: ['secrets-list', mount, path],
    queryFn: () => listSecrets(mount, path),
    enabled: open && isFolder,
    retry: false,
  })

  const children = data?.data?.keys ?? []

  const handleClick = () => {
    if (isFolder) {
      setOpen((o) => !o)
    } else {
      navigate(`/secrets/${mount}/${path}`)
    }
  }

  const displayName = label.replace(/\/$/, '')

  return (
    <div>
      <button
        onClick={handleClick}
        className="w-full flex items-center gap-1.5 px-2 py-1 rounded text-xs text-muted hover:text-txt hover:bg-surface-2 transition-colors text-left"
        style={{ paddingLeft: `${8 + depth * 12}px` }}
      >
        {isFolder ? (
          <>
            {open ? (
              <ChevronDown size={12} className="flex-shrink-0 text-muted" />
            ) : (
              <ChevronRight size={12} className="flex-shrink-0 text-muted" />
            )}
            {open ? (
              <FolderOpen size={12} className="flex-shrink-0 text-accent" />
            ) : (
              <Folder size={12} className="flex-shrink-0 text-muted" />
            )}
          </>
        ) : (
          <>
            <span className="w-3 flex-shrink-0" />
            <FileKey size={12} className="flex-shrink-0 text-muted" />
          </>
        )}
        <span className="truncate">{displayName}</span>
      </button>
      {open && isFolder && children.length > 0 && (
        <div>
          {children.map((child) => (
            <TreeNode
              key={child}
              mount={mount}
              path={path ? `${path}/${child.replace(/\/$/, '')}` : child.replace(/\/$/, '')}
              label={child}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function MountTree({ mountPath }: { mountPath: string }) {
  const [open, setOpen] = useState(true)

  const { data } = useQuery({
    queryKey: ['secrets-list', mountPath, ''],
    queryFn: () => listSecrets(mountPath, ''),
    enabled: open,
    retry: false,
  })

  const children = data?.data?.keys ?? []

  return (
    <div className="mb-1">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-1.5 px-2 py-1.5 rounded text-xs font-medium text-txt hover:bg-surface-2 transition-colors text-left"
      >
        {open ? (
          <ChevronDown size={12} className="text-muted flex-shrink-0" />
        ) : (
          <ChevronRight size={12} className="text-muted flex-shrink-0" />
        )}
        <Key size={12} className="text-accent flex-shrink-0" />
        <span className="truncate">{mountPath}</span>
      </button>
      {open && (
        <div className="ml-1">
          {children.map((key) => (
            <TreeNode
              key={key}
              mount={mountPath}
              path={key.replace(/\/$/, '')}
              label={key}
              depth={1}
            />
          ))}
          {children.length === 0 && (
            <p className="text-xs text-muted px-4 py-1 italic">empty</p>
          )}
        </div>
      )}
    </div>
  )
}

interface SidebarProps {
  expanded: boolean
}

export function Sidebar({ expanded }: SidebarProps) {
  const { data: mounts } = useQuery({
    queryKey: ['mounts'],
    queryFn: listMounts,
    retry: false,
  })

  const mountKeys = Object.keys(mounts ?? {}).filter(
    (k) => !k.startsWith('sys/') && !k.startsWith('identity/') && !k.startsWith('cubbyhole/')
  )

  return (
    <aside
      className={`flex flex-col h-full bg-surface border-r border-border transition-sidebar overflow-hidden ${
        expanded ? 'w-56' : 'w-16'
      }`}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-4 border-b border-border flex-shrink-0">
        <div className="w-8 h-8 rounded-lg bg-accent-dim flex items-center justify-center flex-shrink-0">
          <Lock size={15} className="text-accent" />
        </div>
        {expanded && (
          <span className="font-mono text-sm font-semibold text-txt tracking-tight">
            secretd
          </span>
        )}
      </div>

      {/* Nav */}
      <nav className="flex flex-col gap-0.5 p-2 flex-shrink-0">
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-accent-dim text-accent font-medium'
                  : 'text-muted hover:text-txt hover:bg-surface-2'
              }`
            }
          >
            <Icon size={16} className="flex-shrink-0" />
            {expanded && <span className="truncate">{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Mount tree (only when expanded and on /secrets) */}
      {expanded && mountKeys.length > 0 && (
        <div className="flex-1 overflow-y-auto px-2 pb-2 min-h-0">
          <p className="text-xs text-muted font-medium uppercase tracking-widest px-2 py-3">
            Mounts
          </p>
          {mountKeys.map((mount) => (
            <MountTree key={mount} mountPath={mount.replace(/\/$/, '')} />
          ))}
        </div>
      )}

      {/* Bottom spacer */}
      <div className="flex-1" />

      {/* Settings */}
      <div className="p-2 border-t border-border flex-shrink-0">
        <button className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-muted hover:text-txt hover:bg-surface-2 transition-colors w-full">
          <Settings size={16} className="flex-shrink-0" />
          {expanded && <span className="truncate">Settings</span>}
        </button>
      </div>
    </aside>
  )
}
