"use client"

import { useEffect, useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
    Loader2,
    Globe,
    Upload,
    Download,
    FileJson,
    FileCode2,
    Key,
    Shield,
    ShieldAlert,
    ShieldCheck,
    Server,
    ChevronDown,
    ChevronRight,
    AlertTriangle,
    CheckCircle2,
    XCircle,
    ExternalLink,
    FolderOpen,
    Zap
} from "lucide-react"

// =============================================================================
// Types
// =============================================================================

interface APIEndpoint {
    category: string
    rule_id: string
    path: string
    line: number
    code: string
    endpoint_path?: string
    message: string
    metadata: {
        category: string
        subcategory: string
        secret_type?: string
        environment?: string
        framework?: string
    }
}

interface APIAuditData {
    repository: string
    timestamp: string
    inbound_endpoints: APIEndpoint[]
    outbound_endpoints: APIEndpoint[]
    auth_patterns: APIEndpoint[]
    fingerprint: {
        language: string | null
        frameworks: string[]
        http_clients: string[]
        config_sources: string[]
    }
    servers: { url: string; description?: string }[]
    credentials: {
        high: CredentialFinding[]
        medium: CredentialFinding[]
        low: CredentialFinding[]
    }
}

interface CredentialFinding {
    type: string
    environment: string
    file: string
    code: string
    attack_vector?: string
}

interface APIAuditViewProps {
    projectId: string
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

// =============================================================================
// Component
// =============================================================================

export function APIAuditView({ projectId }: APIAuditViewProps) {
    const [auditData, setAuditData] = useState<APIAuditData | null>(null)
    const [openApiSpec, setOpenApiSpec] = useState<string | null>(null)
    const [swaggerFiles, setSwaggerFiles] = useState<Array<{ name: string, server_url: string, yaml_file: string, json_file: string | null, path_count: number }>>([])
    const [matchedCredentials, setMatchedCredentials] = useState<Array<{ service: string, type: string, value: string, certainty: number, server_url: string }>>([])
    const [credentialsModalOpen, setCredentialsModalOpen] = useState(false)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)
    const [activeTab, setActiveTab] = useState("results")
    const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(["servers", "credentials"]))
    const [swaggerModalUrl, setSwaggerModalUrl] = useState<string | null>(null)

    useEffect(() => {
        fetchAuditData()
        fetchSwaggerFiles()
        fetchMatchedCredentials()
    }, [projectId])

    const fetchMatchedCredentials = async () => {
        try {
            const response = await fetch(`${API_BASE}/projects/${projectId}/api-audit/matched-credentials`)
            if (response.ok) {
                const data = await response.json()
                setMatchedCredentials(data.credentials || [])
            }
        } catch (e) {
            console.error("Failed to fetch matched credentials:", e)
        }
    }

    const fetchSwaggerFiles = async () => {
        try {
            const response = await fetch(`${API_BASE}/projects/${projectId}/api-audit/swagger-files`)
            if (response.ok) {
                const data = await response.json()
                setSwaggerFiles(data.files || [])
            }
        } catch (e) {
            console.error("Failed to fetch swagger files:", e)
        }
    }

    const fetchAuditData = async () => {
        setLoading(true)
        setError(null)
        try {
            const [auditRes, specRes] = await Promise.all([
                fetch(`${API_BASE}/projects/${projectId}/api-audit/full-report`),
                fetch(`${API_BASE}/projects/${projectId}/api-audit/openapi/view`)
            ])

            if (auditRes.ok) {
                const data = await auditRes.json()
                setAuditData(data)
            } else if (auditRes.status === 404) {
                setError("No API audit data found. Run an API audit scan first.")
            }

            if (specRes.ok) {
                const spec = await specRes.json()
                setOpenApiSpec(spec.spec_content)
            }
        } catch (err) {
            console.error("Failed to fetch API audit data:", err)
            setError("Failed to connect to API server.")
        } finally {
            setLoading(false)
        }
    }

    const toggleSection = (section: string) => {
        const newExpanded = new Set(expandedSections)
        if (newExpanded.has(section)) {
            newExpanded.delete(section)
        } else {
            newExpanded.add(section)
        }
        setExpandedSections(newExpanded)
    }

    const handleDownload = (format: "yaml" | "json") => {
        window.open(`${API_BASE}/projects/${projectId}/api-audit/openapi?format=${format}`, '_blank')
    }

    // =========================================================================
    // Render Helpers
    // =========================================================================

    const renderSeverityBadge = (severity: "high" | "medium" | "low", count: number) => {
        const configs = {
            high: { bg: "bg-red-500/10 border-red-500/30", text: "text-red-500", icon: XCircle, label: "HIGH" },
            medium: { bg: "bg-yellow-500/10 border-yellow-500/30", text: "text-yellow-500", icon: AlertTriangle, label: "MEDIUM" },
            low: { bg: "bg-green-500/10 border-green-500/30", text: "text-green-500", icon: CheckCircle2, label: "LOW" }
        }
        const config = configs[severity]
        const Icon = config.icon

        return (
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${config.bg}`}>
                <Icon className={`h-4 w-4 ${config.text}`} />
                <span className={`font-semibold ${config.text}`}>{count}</span>
                <span className="text-xs text-muted-foreground">{config.label}</span>
            </div>
        )
    }

    const groupServersByEnvironment = (servers: { url: string }[]) => {
        const groups = { production: [] as string[], staging: [] as string[], development: [] as string[], other: [] as string[] }

        servers.forEach(s => {
            const url = s.url.toLowerCase()
            if (url.includes('prod') || (url.includes('api.') && !url.includes('dev') && !url.includes('stage') && !url.includes('test'))) {
                groups.production.push(s.url)
            } else if (url.includes('stage')) {
                groups.staging.push(s.url)
            } else if (url.includes('dev') || url.includes('test') || url.includes('qa')) {
                groups.development.push(s.url)
            } else {
                groups.other.push(s.url)
            }
        })

        return groups
    }

    // =========================================================================
    // Loading State
    // =========================================================================

    if (loading) {
        return (
            <div className="flex h-64 items-center justify-center">
                <div className="flex flex-col items-center gap-4">
                    <Loader2 className="h-10 w-10 animate-spin text-primary" />
                    <p className="text-muted-foreground">Loading API Audit data...</p>
                </div>
            </div>
        )
    }

    if (error) {
        return (
            <div className="flex h-64 items-center justify-center">
                <Card className="max-w-md">
                    <CardContent className="flex flex-col items-center gap-4 pt-6">
                        <ShieldAlert className="h-12 w-12 text-muted-foreground" />
                        <p className="text-center text-muted-foreground">{error}</p>
                        <Button variant="outline" onClick={fetchAuditData}>
                            Retry
                        </Button>
                    </CardContent>
                </Card>
            </div>
        )
    }

    if (!auditData) {
        return (
            <div className="flex h-64 items-center justify-center">
                <Card className="max-w-md">
                    <CardContent className="flex flex-col items-center gap-4 pt-6">
                        <FileCode2 className="h-12 w-12 text-muted-foreground" />
                        <p className="text-center text-muted-foreground">
                            No API audit data available. Run an API scan to discover endpoints.
                        </p>
                    </CardContent>
                </Card>
            </div>
        )
    }

    const serverGroups = groupServersByEnvironment(auditData.servers || [])
    const totalCredentials =
        (auditData.credentials?.high?.length || 0) +
        (auditData.credentials?.medium?.length || 0) +
        (auditData.credentials?.low?.length || 0)

    // =========================================================================
    // Main Render
    // =========================================================================

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight">API Security Audit</h2>
                    <p className="text-muted-foreground">
                        Discovered APIs, credentials, and security findings from static analysis.
                    </p>
                </div>

                {/* Download Button */}
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="outline" className="gap-2">
                            <Download className="h-4 w-4" />
                            Download Spec
                            <ChevronDown className="h-4 w-4" />
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => handleDownload("yaml")}>
                            <FileCode2 className="h-4 w-4 mr-2" />
                            OpenAPI (YAML)
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleDownload("json")}>
                            <FileJson className="h-4 w-4 mr-2" />
                            OpenAPI (JSON)
                        </DropdownMenuItem>
                    </DropdownMenuContent>
                </DropdownMenu>
            </div>

            {/* Tabs */}
            <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
                <TabsList className="grid w-full max-w-md grid-cols-2">
                    <TabsTrigger value="results" className="gap-2">
                        <Shield className="h-4 w-4" />
                        Results
                    </TabsTrigger>
                    <TabsTrigger value="swagger" className="gap-2">
                        <Zap className="h-4 w-4" />
                        SwaggerUI
                    </TabsTrigger>
                </TabsList>

                {/* ============================================================ */}
                {/* RESULTS TAB */}
                {/* ============================================================ */}
                <TabsContent value="results" className="space-y-6">

                    {/* Executive Summary Cards */}
                    <div className="grid gap-4 md:grid-cols-4">
                        <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20">
                            <CardHeader className="pb-2">
                                <CardDescription className="flex items-center gap-2">
                                    <Globe className="h-4 w-4" />
                                    Inbound APIs
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <div className="text-3xl font-bold">{auditData.inbound_endpoints.length}</div>
                                <p className="text-xs text-muted-foreground">APIs this project serves</p>
                            </CardContent>
                        </Card>

                        <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/20">
                            <CardHeader className="pb-2">
                                <CardDescription className="flex items-center gap-2">
                                    <Upload className="h-4 w-4" />
                                    Outbound APIs
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <div className="text-3xl font-bold">{auditData.outbound_endpoints.length}</div>
                                <p className="text-xs text-muted-foreground">External APIs consumed</p>
                            </CardContent>
                        </Card>

                        <Card className="bg-gradient-to-br from-green-500/10 to-green-600/5 border-green-500/20">
                            <CardHeader className="pb-2">
                                <CardDescription className="flex items-center gap-2">
                                    <Server className="h-4 w-4" />
                                    API Servers
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <div className="text-3xl font-bold">{auditData.servers?.length || 0}</div>
                                <p className="text-xs text-muted-foreground">Discovered server URLs</p>
                            </CardContent>
                        </Card>

                        <Card className="bg-gradient-to-br from-orange-500/10 to-orange-600/5 border-orange-500/20">
                            <CardHeader className="pb-2">
                                <CardDescription className="flex items-center gap-2">
                                    <Key className="h-4 w-4" />
                                    Credentials
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <div className="text-3xl font-bold">{totalCredentials}</div>
                                <p className="text-xs text-muted-foreground">Hardcoded secrets found</p>
                            </CardContent>
                        </Card>
                    </div>

                    {/* Credential Risk Assessment */}
                    {totalCredentials > 0 && (
                        <Collapsible open={expandedSections.has("credentials")} onOpenChange={() => toggleSection("credentials")}>
                            <Card>
                                <CollapsibleTrigger asChild>
                                    <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <ShieldAlert className="h-5 w-5 text-orange-500" />
                                                <div>
                                                    <CardTitle className="text-lg">Hardcoded Credentials Risk Assessment</CardTitle>
                                                    <CardDescription>API keys, tokens, and secrets found in source code</CardDescription>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-4">
                                                <div className="flex gap-2">
                                                    {(auditData.credentials?.high?.length || 0) > 0 && renderSeverityBadge("high", auditData.credentials.high.length)}
                                                    {(auditData.credentials?.medium?.length || 0) > 0 && renderSeverityBadge("medium", auditData.credentials.medium.length)}
                                                    {(auditData.credentials?.low?.length || 0) > 0 && renderSeverityBadge("low", auditData.credentials.low.length)}
                                                </div>
                                                {expandedSections.has("credentials") ? <ChevronDown className="h-5 w-5" /> : <ChevronRight className="h-5 w-5" />}
                                            </div>
                                        </div>
                                    </CardHeader>
                                </CollapsibleTrigger>
                                <CollapsibleContent>
                                    <CardContent className="space-y-6">
                                        {/* High Risk */}
                                        {(auditData.credentials?.high?.length || 0) > 0 && (
                                            <div className="space-y-3">
                                                <div className="flex items-center gap-2">
                                                    <XCircle className="h-4 w-4 text-red-500" />
                                                    <h4 className="font-semibold text-red-500">High Risk</h4>
                                                    <span className="text-xs text-muted-foreground">— May allow infrastructure access or service impersonation</span>
                                                </div>
                                                <div className="rounded-lg border border-red-500/20 bg-red-500/5 overflow-hidden">
                                                    <table className="w-full text-sm">
                                                        <thead className="bg-red-500/10">
                                                            <tr>
                                                                <th className="px-4 py-2 text-left font-medium">Type</th>
                                                                <th className="px-4 py-2 text-left font-medium">Environment</th>
                                                                <th className="px-4 py-2 text-left font-medium">File</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {auditData.credentials.high.slice(0, 10).map((cred, i) => (
                                                                <tr key={i} className="border-t border-red-500/10">
                                                                    <td className="px-4 py-2 font-mono text-xs">{cred.type}</td>
                                                                    <td className="px-4 py-2">
                                                                        <Badge variant="outline" className="text-xs">{cred.environment}</Badge>
                                                                    </td>
                                                                    <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{cred.file}</td>
                                                                </tr>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </div>
                                        )}

                                        {/* Medium Risk */}
                                        {(auditData.credentials?.medium?.length || 0) > 0 && (
                                            <div className="space-y-3">
                                                <div className="flex items-center gap-2">
                                                    <AlertTriangle className="h-4 w-4 text-yellow-500" />
                                                    <h4 className="font-semibold text-yellow-500">Medium Risk</h4>
                                                    <span className="text-xs text-muted-foreground">— Allows data injection, analytics pollution, or API abuse</span>
                                                </div>
                                                <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 overflow-hidden">
                                                    <table className="w-full text-sm">
                                                        <thead className="bg-yellow-500/10">
                                                            <tr>
                                                                <th className="px-4 py-2 text-left font-medium">Type</th>
                                                                <th className="px-4 py-2 text-left font-medium">Environment</th>
                                                                <th className="px-4 py-2 text-left font-medium">Attack Vector</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {auditData.credentials.medium.slice(0, 10).map((cred, i) => (
                                                                <tr key={i} className="border-t border-yellow-500/10">
                                                                    <td className="px-4 py-2 font-mono text-xs">{cred.type}</td>
                                                                    <td className="px-4 py-2">
                                                                        <Badge variant="outline" className="text-xs">{cred.environment}</Badge>
                                                                    </td>
                                                                    <td className="px-4 py-2 text-xs text-muted-foreground">{cred.attack_vector || "API abuse, data injection"}</td>
                                                                </tr>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </div>
                                        )}

                                        {/* Low Risk */}
                                        {(auditData.credentials?.low?.length || 0) > 0 && (
                                            <div className="space-y-3">
                                                <div className="flex items-center gap-2">
                                                    <CheckCircle2 className="h-4 w-4 text-green-500" />
                                                    <h4 className="font-semibold text-green-500">Low Risk</h4>
                                                    <span className="text-xs text-muted-foreground">— Public OAuth client IDs, useful for API reconnaissance</span>
                                                </div>
                                                <p className="text-sm text-muted-foreground">
                                                    Found {auditData.credentials.low.length} OAuth client IDs (Cognito, etc.) — typically public but confirm API surface.
                                                </p>
                                            </div>
                                        )}
                                    </CardContent>
                                </CollapsibleContent>
                            </Card>
                        </Collapsible>
                    )}

                    {/* Discovered API Servers */}
                    {(auditData.servers?.length || 0) > 0 && (
                        <Collapsible open={expandedSections.has("servers")} onOpenChange={() => toggleSection("servers")}>
                            <Card>
                                <CollapsibleTrigger asChild>
                                    <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <Server className="h-5 w-5 text-green-500" />
                                                <div>
                                                    <CardTitle className="text-lg">Discovered API Servers</CardTitle>
                                                    <CardDescription>Server URLs extracted from configuration files</CardDescription>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-4">
                                                <Badge variant="secondary">{auditData.servers.length} servers</Badge>
                                                {expandedSections.has("servers") ? <ChevronDown className="h-5 w-5" /> : <ChevronRight className="h-5 w-5" />}
                                            </div>
                                        </div>
                                    </CardHeader>
                                </CollapsibleTrigger>
                                <CollapsibleContent>
                                    <CardContent>
                                        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                                            {serverGroups.production.length > 0 && (
                                                <div className="space-y-2">
                                                    <h4 className="font-semibold text-sm flex items-center gap-2">
                                                        <div className="h-2 w-2 rounded-full bg-green-500" />
                                                        Production ({serverGroups.production.length})
                                                    </h4>
                                                    <div className="space-y-1">
                                                        {serverGroups.production.slice(0, 5).map((url, i) => (
                                                            <div key={i} className="flex items-center gap-2 text-xs font-mono bg-muted/50 px-2 py-1 rounded">
                                                                <Globe className="h-3 w-3 flex-shrink-0" />
                                                                <span className="truncate">{url}</span>
                                                            </div>
                                                        ))}
                                                        {serverGroups.production.length > 5 && (
                                                            <p className="text-xs text-muted-foreground">...and {serverGroups.production.length - 5} more</p>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            {serverGroups.staging.length > 0 && (
                                                <div className="space-y-2">
                                                    <h4 className="font-semibold text-sm flex items-center gap-2">
                                                        <div className="h-2 w-2 rounded-full bg-yellow-500" />
                                                        Staging ({serverGroups.staging.length})
                                                    </h4>
                                                    <div className="space-y-1">
                                                        {serverGroups.staging.slice(0, 5).map((url, i) => (
                                                            <div key={i} className="flex items-center gap-2 text-xs font-mono bg-muted/50 px-2 py-1 rounded">
                                                                <Globe className="h-3 w-3 flex-shrink-0" />
                                                                <span className="truncate">{url}</span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}

                                            {serverGroups.development.length > 0 && (
                                                <div className="space-y-2">
                                                    <h4 className="font-semibold text-sm flex items-center gap-2">
                                                        <div className="h-2 w-2 rounded-full bg-blue-500" />
                                                        Development/QA ({serverGroups.development.length})
                                                    </h4>
                                                    <div className="space-y-1">
                                                        {serverGroups.development.slice(0, 5).map((url, i) => (
                                                            <div key={i} className="flex items-center gap-2 text-xs font-mono bg-muted/50 px-2 py-1 rounded">
                                                                <Globe className="h-3 w-3 flex-shrink-0" />
                                                                <span className="truncate">{url}</span>
                                                            </div>
                                                        ))}
                                                        {serverGroups.development.length > 5 && (
                                                            <p className="text-xs text-muted-foreground">...and {serverGroups.development.length - 5} more</p>
                                                        )}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </CardContent>
                                </CollapsibleContent>
                            </Card>
                        </Collapsible>
                    )}

                    {/* Configuration Sources */}
                    {(auditData.fingerprint?.config_sources?.length || 0) > 0 && (
                        <Card>
                            <CardHeader>
                                <div className="flex items-center gap-3">
                                    <FolderOpen className="h-5 w-5 text-blue-500" />
                                    <div>
                                        <CardTitle className="text-lg">Configuration Sources</CardTitle>
                                        <CardDescription>Files where API configuration was discovered</CardDescription>
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="flex flex-wrap gap-2">
                                    {auditData.fingerprint.config_sources.map((source, i) => (
                                        <Badge key={i} variant="secondary" className="font-mono text-xs">
                                            {source}
                                        </Badge>
                                    ))}
                                </div>
                            </CardContent>
                        </Card>
                    )}
                </TabsContent>

                {/* ============================================================ */}
                {/* SWAGGER UI TAB */}
                {/* ============================================================ */}
                <TabsContent value="swagger" className="space-y-4">
                    <Card className="overflow-hidden">
                        <CardHeader className="bg-muted/30 border-b">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <Zap className="h-5 w-5 text-primary" />
                                    <div>
                                        <CardTitle className="text-lg">Interactive API Explorer</CardTitle>
                                        <CardDescription>Test and inspect API endpoints using SwaggerUI</CardDescription>
                                    </div>
                                </div>
                                <div className="flex gap-2">
                                    <Button
                                        variant="default"
                                        size="sm"
                                        onClick={() => window.open(`${API_BASE}/projects/${projectId}/api-audit/server-testing`, '_blank')}
                                    >
                                        🔍 API Discovery
                                    </Button>
                                </div>
                            </div>
                        </CardHeader>
                        <CardContent className="p-4">
                            {swaggerFiles.length > 0 ? (
                                <div className="rounded-lg border overflow-hidden">
                                    <table className="w-full">
                                        <thead className="bg-muted/50">
                                            <tr>
                                                <th className="text-left p-3 font-medium text-sm">Server Path</th>
                                                <th className="text-center p-3 font-medium text-sm w-24">OpenAPI</th>
                                                <th className="text-center p-3 font-medium text-sm w-24">Swagger</th>
                                                <th className="text-center p-3 font-medium text-sm w-32">Action</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {swaggerFiles.map((file, idx) => (
                                                <tr key={idx} className="border-t hover:bg-muted/30">
                                                    <td className="p-3">
                                                        <div className="flex flex-col">
                                                            <span className="font-mono text-sm truncate max-w-md" title={file.server_url}>
                                                                {file.server_url || file.name}
                                                            </span>
                                                            <span className="text-xs text-muted-foreground">
                                                                {file.path_count} endpoint{file.path_count !== 1 ? 's' : ''}
                                                            </span>
                                                        </div>
                                                    </td>
                                                    <td className="p-3 text-center">
                                                        {file.json_file && (
                                                            <Button
                                                                variant="outline"
                                                                size="sm"
                                                                onClick={() => window.open(`${API_BASE}/projects/${projectId}/api-audit/swagger-file/${file.json_file}`, '_blank')}
                                                                title="Download JSON"
                                                            >
                                                                <Download className="h-4 w-4" />
                                                                <span className="ml-1 text-xs">JSON</span>
                                                            </Button>
                                                        )}
                                                    </td>
                                                    <td className="p-3 text-center">
                                                        <Button
                                                            variant="outline"
                                                            size="sm"
                                                            onClick={() => window.open(`${API_BASE}/projects/${projectId}/api-audit/swagger-file/${file.yaml_file}`, '_blank')}
                                                            title="Download YAML"
                                                        >
                                                            <Download className="h-4 w-4" />
                                                            <span className="ml-1 text-xs">YAML</span>
                                                        </Button>
                                                    </td>
                                                    <td className="p-3 text-center">
                                                        <Button
                                                            variant="default"
                                                            size="sm"
                                                            onClick={() => setSwaggerModalUrl(`${API_BASE}/projects/${projectId}/api-audit/swagger-file/${file.json_file || file.yaml_file}`)}
                                                        >
                                                            <ExternalLink className="h-4 w-4 mr-1" />
                                                            SwaggerUI
                                                        </Button>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            ) : (
                                <div className="flex flex-col items-center justify-center h-48 text-center">
                                    <FileCode2 className="h-12 w-12 text-muted-foreground mb-4" />
                                    <p className="text-muted-foreground">
                                        No Swagger specifications available.
                                    </p>
                                    <p className="text-sm text-muted-foreground mt-2">
                                        Use API Discovery to generate swagger files for each server.
                                    </p>
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        className="mt-4"
                                        onClick={() => window.open(`${API_BASE}/projects/${projectId}/api-audit/server-testing`, '_blank')}
                                    >
                                        🔍 Open API Discovery
                                    </Button>
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {/* AI Matched Credentials */}
                    <Card className="overflow-hidden">
                        <CardHeader className="bg-muted/30 border-b py-3">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <Key className="h-4 w-4 text-primary" />
                                    <CardTitle className="text-base">AI-Matched Credentials</CardTitle>
                                    {matchedCredentials.filter(c => c.certainty >= 80).length > 0 && (
                                        <Badge variant="secondary" className="ml-2">
                                            {matchedCredentials.filter(c => c.certainty >= 80).length} high confidence
                                        </Badge>
                                    )}
                                </div>
                                {matchedCredentials.length > 3 && (
                                    <Button variant="outline" size="sm" onClick={() => setCredentialsModalOpen(true)}>
                                        View All ({matchedCredentials.length})
                                    </Button>
                                )}
                            </div>
                        </CardHeader>
                        <CardContent className="p-4">
                            {matchedCredentials.filter(c => c.certainty >= 80).length > 0 ? (
                                <div className="rounded-lg border overflow-hidden">
                                    <table className="w-full">
                                        <thead className="bg-muted/50">
                                            <tr>
                                                <th className="text-left p-3 font-medium text-sm">Service</th>
                                                <th className="text-left p-3 font-medium text-sm">Type</th>
                                                <th className="text-left p-3 font-medium text-sm">Value</th>
                                                <th className="text-center p-3 font-medium text-sm w-24">Certainty</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {matchedCredentials.filter(c => c.certainty >= 80).slice(0, 3).map((cred, idx) => (
                                                <tr key={idx} className="border-t hover:bg-muted/30">
                                                    <td className="p-3">
                                                        <span className="font-medium">{cred.service}</span>
                                                    </td>
                                                    <td className="p-3">
                                                        <Badge variant="outline">{cred.type}</Badge>
                                                    </td>
                                                    <td className="p-3">
                                                        <code className="text-xs bg-muted px-2 py-1 rounded font-mono break-all">
                                                            {cred.value}
                                                        </code>
                                                    </td>
                                                    <td className="p-3 text-center">
                                                        <Badge className={cred.certainty >= 90 ? 'bg-green-500' : cred.certainty >= 80 ? 'bg-yellow-500' : 'bg-gray-500'}>
                                                            {cred.certainty}%
                                                        </Badge>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            ) : (
                                <div className="flex flex-col items-center justify-center h-24 text-center">
                                    <p className="text-muted-foreground text-sm">
                                        No high-confidence credential matches found.
                                    </p>
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {/* Credentials Modal */}
                    {credentialsModalOpen && (
                        <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
                            <div className="bg-white dark:bg-black rounded-lg w-full max-w-4xl max-h-[80vh] flex flex-col overflow-hidden shadow-2xl border dark:border-zinc-800">
                                <div className="flex items-center justify-between p-4 border-b">
                                    <h2 className="text-lg font-semibold">All Matched Credentials ({matchedCredentials.length})</h2>
                                    <Button variant="ghost" size="sm" onClick={() => setCredentialsModalOpen(false)}>
                                        <XCircle className="h-5 w-5" />
                                    </Button>
                                </div>
                                <div className="flex-1 overflow-auto p-4">
                                    <table className="w-full">
                                        <thead className="bg-muted/50 sticky top-0">
                                            <tr>
                                                <th className="text-left p-3 font-medium text-sm">Service</th>
                                                <th className="text-left p-3 font-medium text-sm">Type</th>
                                                <th className="text-left p-3 font-medium text-sm">Value</th>
                                                <th className="text-center p-3 font-medium text-sm w-24">Certainty</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {matchedCredentials.map((cred, idx) => (
                                                <tr key={idx} className="border-t hover:bg-muted/30">
                                                    <td className="p-3">
                                                        <span className="font-medium">{cred.service}</span>
                                                    </td>
                                                    <td className="p-3">
                                                        <Badge variant="outline">{cred.type}</Badge>
                                                    </td>
                                                    <td className="p-3">
                                                        <code className="text-xs bg-muted px-2 py-1 rounded font-mono break-all">
                                                            {cred.value}
                                                        </code>
                                                    </td>
                                                    <td className="p-3 text-center">
                                                        <Badge className={cred.certainty >= 90 ? 'bg-green-500' : cred.certainty >= 80 ? 'bg-yellow-500' : 'bg-gray-500'}>
                                                            {cred.certainty}%
                                                        </Badge>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* SwaggerUI Modal */}
                    {swaggerModalUrl && (
                        <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
                            <div className="bg-white dark:bg-black rounded-lg w-full max-w-6xl h-[90vh] flex flex-col overflow-hidden shadow-2xl border dark:border-zinc-800">
                                <div className="flex items-center justify-between p-4 border-b">
                                    <h2 className="text-lg font-semibold">SwaggerUI</h2>
                                    <Button variant="ghost" size="sm" onClick={() => setSwaggerModalUrl(null)}>
                                        <XCircle className="h-5 w-5" />
                                    </Button>
                                </div>
                                <div className="flex-1 overflow-hidden">
                                    <iframe
                                        src={`${API_BASE}/projects/${projectId}/api-audit/swagger?spec_url=${encodeURIComponent(swaggerModalUrl)}`}
                                        className="w-full h-full border-0"
                                        title="SwaggerUI"
                                    />
                                </div>
                            </div>
                        </div>
                    )}
                </TabsContent>
            </Tabs>
        </div>
    )
}
