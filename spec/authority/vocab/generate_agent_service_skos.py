"""Generate agent-service-categories.ttl (SKOS 3-level hierarchy)."""
from pathlib import Path

BASE = "https://w3id.org/avp-micro/cat"
# Turtle: @base <BASE> + <#LocalName> → BASE#LocalName (portable; BASE ending in # breaks some parsers)
# Scheme lives outside the hash namespace
SCHEME_PREFIX = f"{BASE}/scheme/"

# (top_id, label, [(l2_id, l2_label, [(leaf_id, leaf_label), ...]), ...])
HIERARCHY = [
    (
        "ComputeAndInference",
        "Compute and inference",
        [
            (
                "TextAndReasoningModels",
                "Text and reasoning models",
                [
                    ("ChatCompletionApi", "Chat completion API"),
                    ("ToolUseFunctionCalling", "Tool use / function calling"),
                    ("StructuredJsonOutput", "Structured JSON / schema-constrained output"),
                    ("LongContextReasoning", "Long-context reasoning"),
                ],
            ),
            (
                "VisionAndMultimodalModels",
                "Vision and multimodal models",
                [
                    ("ImageCaptioningVqa", "Image captioning and VQA"),
                    ("DocumentOcrLayout", "Document OCR and layout"),
                    ("VideoUnderstanding", "Video understanding"),
                    ("MultimodalFusion", "Multimodal fusion models"),
                ],
            ),
            (
                "AudioSpeechModels",
                "Audio and speech models",
                [
                    ("SpeechToText", "Speech-to-text"),
                    ("TextToSpeech", "Text-to-speech"),
                    ("SpeakerDiarization", "Speaker diarization"),
                    ("VoiceBiometrics", "Voice biometrics"),
                ],
            ),
            (
                "EmbeddingsAndSimilarity",
                "Embeddings and similarity",
                [
                    ("TextEmbeddings", "Text embeddings"),
                    ("MultimodalEmbeddings", "Multimodal embeddings"),
                    ("SemanticReranking", "Semantic reranking"),
                    ("DuplicateNearDuplicateDetection", "Duplicate / near-duplicate detection"),
                ],
            ),
            (
                "InferenceRealtime",
                "Realtime inference",
                [
                    ("LowLatencyLlm", "Low-latency LLM API"),
                    ("StreamingTokenInference", "Streaming token inference"),
                    ("EdgeDeviceInference", "Edge / on-device inference"),
                ],
            ),
            (
                "InferenceBatch",
                "Batch inference",
                [
                    ("AsyncBatchScoring", "Async batch scoring"),
                    ("BatchContentGeneration", "Batch content generation"),
                    ("OfflineEvaluationRuns", "Offline evaluation runs"),
                ],
            ),
            (
                "TrainingAndFineTuning",
                "Training and fine-tuning",
                [
                    ("SupervisedFineTuning", "Supervised fine-tuning"),
                    ("PreferenceAlignmentRlhf", "Preference alignment / RLHF"),
                    ("CustomModelTraining", "Custom model training"),
                ],
            ),
            (
                "SandboxedCodeExecution",
                "Sandboxed code execution",
                [
                    ("ContainerSandboxApi", "Container sandbox API"),
                    ("NotebookInteractiveExecution", "Notebook / interactive execution"),
                    ("EphemeralRuntimeSessions", "Ephemeral runtime sessions"),
                ],
            ),
        ],
    ),
    (
        "DataKnowledgeAndFeeds",
        "Data, knowledge, and feeds",
        [
            (
                "BulkDatasetsAndSnapshots",
                "Bulk datasets and snapshots",
                [
                    ("TabularFileBundles", "Tabular file bundles"),
                    ("WarehouseTableExports", "Warehouse table exports"),
                    ("LabeledDatasetSales", "Labeled dataset sales"),
                ],
            ),
            (
                "LiveQueryAndRecordApis",
                "Live query and record APIs",
                [
                    ("RestRecordCrud", "REST record CRUD"),
                    ("GraphqlDataApi", "GraphQL data API"),
                    ("SqlOverHttpOrWire", "SQL over HTTP / wire"),
                ],
            ),
            (
                "StreamsAndPubSub",
                "Streams and pub/sub",
                [
                    ("KafkaCompatibleStreams", "Kafka-compatible streams"),
                    ("WebsocketEventFeeds", "WebSocket event feeds"),
                    ("MqttDeviceStreams", "MQTT device streams"),
                ],
            ),
            (
                "SearchIndexAndDiscovery",
                "Search, index, and discovery",
                [
                    ("FullTextSearchApi", "Full-text search API"),
                    ("VectorHybridSearch", "Vector / hybrid search"),
                    ("FacetedCatalogBrowse", "Faceted catalog browse"),
                ],
            ),
            (
                "KnowledgeBasesCorporaAndRag",
                "Knowledge bases, corpora, and RAG",
                [
                    ("CuratedKbSubscription", "Curated KB subscription"),
                    ("PrivateCorpusHosting", "Private corpus hosting"),
                    ("RagIngestionPipeline", "RAG ingestion pipeline"),
                ],
            ),
            (
                "MarketReferenceAndGeoData",
                "Market, reference, and geo data",
                [
                    ("FinancialMarketDataFeeds", "Financial market data feeds"),
                    ("GeospatialFeatureLayers", "Geospatial feature layers"),
                    ("WeatherAndClimateSeries", "Weather and climate series"),
                ],
            ),
            (
                "WebSearchAndCrawlFeeds",
                "Web search and crawl feeds",
                [
                    ("SerpApiAccess", "SERP API access"),
                    ("CrawlAsAService", "Crawl-as-a-service"),
                    ("StructuredWebExtraction", "Structured web extraction"),
                ],
            ),
            (
                "TimeSeriesAndTelemetryFeeds",
                "Time series and telemetry feeds",
                [
                    ("MetricsAndApmStreams", "Metrics and APM streams"),
                    ("IndustrialSensorTelemetry", "Industrial sensor telemetry"),
                    ("ApplicationLogStreams", "Application log streams"),
                ],
            ),
        ],
    ),
    (
        "ToolingAndIntegration",
        "Tooling and integration",
        [
            (
                "SaasBusinessApplications",
                "SaaS business applications",
                [
                    ("CrmIntegration", "CRM integration"),
                    ("ErpIntegration", "ERP integration"),
                    ("HrAndItsmIntegration", "HR and ITSM integration"),
                ],
            ),
            (
                "CloudDevOpsAndRepos",
                "Cloud, DevOps, and repositories",
                [
                    ("CloudControlPlaneApi", "Cloud control plane API"),
                    ("CicdPipelineIntegration", "CI/CD pipeline integration"),
                    ("SourceRepositoryAutomation", "Source repository automation"),
                ],
            ),
            (
                "WorkflowOrchestration",
                "Workflow orchestration",
                [
                    ("DagWorkflowEngine", "DAG workflow engine"),
                    ("HumanInTheLoopSteps", "Human-in-the-loop steps"),
                    ("EventDrivenOrchestration", "Event-driven orchestration"),
                ],
            ),
            (
                "BrowserDesktopAutomation",
                "Browser and desktop automation",
                [
                    ("HeadlessBrowserAutomation", "Headless browser automation"),
                    ("DesktopRpa", "Desktop RPA"),
                    ("RecordedMacroReplay", "Recorded macro replay"),
                ],
            ),
            (
                "IotDeviceControl",
                "IoT device control",
                [
                    ("DeviceTwinCommands", "Device twin commands"),
                    ("FleetProvisioningUpdates", "Fleet provisioning updates"),
                    ("EdgeRuleDeployment", "Edge rule deployment"),
                ],
            ),
            (
                "DocumentAndContentPlatforms",
                "Document and content platforms",
                [
                    ("CloudDriveFileAutomation", "Cloud drive file automation"),
                    ("WikiKnowledgePageApi", "Wiki / knowledge page API"),
                    ("CmsHeadlessContent", "CMS / headless content"),
                ],
            ),
            (
                "EcommerceOpsAndSellerTools",
                "E-commerce ops and seller tools",
                [
                    ("ListingAndSkuApi", "Listing and SKU API"),
                    ("InventorySync", "Inventory sync"),
                    ("OrderAndFulfillmentHooks", "Order and fulfillment hooks"),
                ],
            ),
            (
                "CollaborationAndMessagingIntegration",
                "Collaboration and messaging integration",
                [
                    ("TeamChatPostingApi", "Team chat posting API"),
                    ("CalendarSchedulingHooks", "Calendar scheduling hooks"),
                    ("IssueTrackerAutomation", "Issue tracker automation"),
                ],
            ),
        ],
    ),
    (
        "MediaAndCreative",
        "Media and creative",
        [
            (
                "ImageGenerationAndEditing",
                "Image generation and editing",
                [
                    ("TextToImageGeneration", "Text-to-image generation"),
                    ("InpaintingOutpainting", "Inpainting / outpainting"),
                    ("BackgroundRemovalEnhancement", "Background removal / enhancement"),
                ],
            ),
            (
                "VideoGenerationAndEditing",
                "Video generation and editing",
                [
                    ("TextOrStoryboardToVideo", "Text / storyboard to video"),
                    ("VideoEditingApi", "Video editing API"),
                    ("SubtitlingAndLocalization", "Subtitling and localization"),
                ],
            ),
            (
                "AudioMusicAndVoiceCreative",
                "Audio, music, and voice (creative)",
                [
                    ("MusicAndSfxGeneration", "Music and SFX generation"),
                    ("VoiceoverProduction", "Voiceover production"),
                    ("PodcastProductionServices", "Podcast production services"),
                ],
            ),
            (
                "StockAndLicensedAssets",
                "Stock and licensed assets",
                [
                    ("RoyaltyFreeStockLibrary", "Royalty-free stock library"),
                    ("RightsManagedLicensing", "Rights-managed licensing"),
                    ("EnterpriseAssetEntitlements", "Enterprise asset entitlements"),
                ],
            ),
            (
                "CopywritingAndLocalizedContent",
                "Copywriting and localized content",
                [
                    ("MarketingCopyPackages", "Marketing copy packages"),
                    ("TranscreationServices", "Transcreation services"),
                    ("SeoAndMetadataPacks", "SEO and metadata packs"),
                ],
            ),
            (
                "DesignTemplatesAndBrandSystems",
                "Design templates and brand systems",
                [
                    ("UiKitAndDesignTokens", "UI kit and design tokens"),
                    ("SlideDeckTemplates", "Slide deck templates"),
                    ("BrandGuidelinePacks", "Brand guideline packs"),
                ],
            ),
            (
                "ThreeDimensionalAndSpatialAssets",
                "3D and spatial assets",
                [
                    ("MeshAndModelMarketplace", "Mesh and model marketplace"),
                    ("ArVrScenePackages", "AR/VR scene packages"),
                    ("CadAndBimDerivatives", "CAD and BIM derivatives"),
                ],
            ),
            (
                "InteractiveAndExperientialMedia",
                "Interactive and experiential media",
                [
                    ("LightweightGamesAndDemos", "Lightweight games and demos"),
                    ("InteractiveAdsAndWidgets", "Interactive ads and widgets"),
                    ("ConfigurableProductDemos", "Configurable product demos"),
                ],
            ),
        ],
    ),
    (
        "CommunicationsAndReach",
        "Communications and reach",
        [
            (
                "EmailDelivery",
                "Email delivery",
                [
                    ("TransactionalEmailApi", "Transactional email API"),
                    ("MarketingEmailCampaigns", "Marketing email campaigns"),
                    ("InboxPlacementAndWarmup", "Inbox placement / warmup"),
                ],
            ),
            (
                "SmsAndMessagingChannels",
                "SMS and messaging channels",
                [
                    ("SmsMmsGateway", "SMS/MMS gateway"),
                    ("RcsAndRichMessaging", "RCS and rich messaging"),
                    ("OtpAndVerificationSms", "OTP and verification SMS"),
                ],
            ),
            (
                "VoiceAndTelephony",
                "Voice and telephony",
                [
                    ("PstnOriginationTermination", "PSTN origination/termination"),
                    ("SipTrunking", "SIP trunking"),
                    ("IvrAndCallControl", "IVR and call control"),
                ],
            ),
            (
                "PushAndInAppMessaging",
                "Push and in-app messaging",
                [
                    ("MobilePushNotifications", "Mobile push notifications"),
                    ("InAppChatSdkBackend", "In-app chat SDK backend"),
                    ("WebPushNotifications", "Web push notifications"),
                ],
            ),
            (
                "PostalAndPhysicalMail",
                "Postal and physical mail",
                [
                    ("PrintAndMailApi", "Print-and-mail API"),
                    ("AddressVerification", "Address verification"),
                    ("CertifiedAndRegisteredMail", "Certified / registered mail"),
                ],
            ),
            (
                "SocialDistribution",
                "Social distribution",
                [
                    ("ScheduledSocialPosting", "Scheduled social posting"),
                    ("PaidSocialBoostApis", "Paid social boost APIs"),
                    ("InfluencerCampaignCoordination", "Influencer campaign coordination"),
                ],
            ),
            (
                "MeetingsAndWebinars",
                "Meetings and webinars",
                [
                    ("VideoConferencingApi", "Video conferencing API"),
                    ("WebinarHosting", "Webinar hosting"),
                    ("RecordingAndTranscriptionHooks", "Recording and transcription hooks"),
                ],
            ),
            (
                "BroadcastAndAlerts",
                "Broadcast and alerts",
                [
                    ("MassNotificationSystems", "Mass notification systems"),
                    ("EmergencyAlertGateways", "Emergency alert gateways"),
                    ("OperationalPaging", "Operational paging"),
                ],
            ),
        ],
    ),
    (
        "HumanServices",
        "Human services",
        [
            (
                "DataLabelingAndAnnotation",
                "Data labeling and annotation",
                [
                    ("ImageVideoBoundingBoxes", "Image/video bounding boxes"),
                    ("NlpSpanAndClassification", "NLP span and classification"),
                    ("LidarAndSensorAnnotation", "LiDAR and sensor annotation"),
                ],
            ),
            (
                "ModerationAndSafetyReview",
                "Moderation and safety review",
                [
                    ("PolicyBasedContentReview", "Policy-based content review"),
                    ("AppealsAndEscalation", "Appeals and escalation"),
                    ("ChildSafetySpecialistReview", "Child safety specialist review"),
                ],
            ),
            (
                "ExpertReviewAndQualityAssurance",
                "Expert review and quality assurance",
                [
                    ("DomainExpertEvaluation", "Domain expert evaluation"),
                    ("RedTeamAndAdversarialReview", "Red team / adversarial review"),
                    ("GoldSetAndBenchmarkCuration", "Gold set / benchmark curation"),
                ],
            ),
            (
                "CreativeProductionByPeople",
                "Creative production by people",
                [
                    ("VideoEditingServices", "Video editing services"),
                    ("GraphicDesignServices", "Graphic design services"),
                    ("PhotoRetouching", "Photo retouching"),
                ],
            ),
            (
                "ResearchSurveysAndInterviews",
                "Research, surveys, and interviews",
                [
                    ("PanelSurveys", "Panel surveys"),
                    ("UserInterviewsRecruitment", "User interviews recruitment"),
                    ("B2bExpertCalls", "B2B expert calls"),
                ],
            ),
            (
                "CustomerSupportAndCxOperations",
                "Customer support and CX operations",
                [
                    ("OutsourcedTier1Support", "Outsourced tier-1 support"),
                    ("BackOfficeTicketHandling", "Back-office ticket handling"),
                    ("QualityMonitoringCoaching", "Quality monitoring / coaching"),
                ],
            ),
            (
                "TranslationAndLocalization",
                "Translation and localization",
                [
                    ("HumanTranslationServices", "Human translation services"),
                    ("LinguisticQa", "Linguistic QA"),
                    ("ContinuousLocalizationWorkflow", "Continuous localization workflow"),
                ],
            ),
            (
                "MicrotasksAndCrowdsourcing",
                "Microtasks and crowdsourcing",
                [
                    ("GeneralMicrotaskMarketplace", "General microtask marketplace"),
                    ("JudgingAndRankingTasks", "Judging and ranking tasks"),
                    ("PaidBetaAndUxTasks", "Paid beta / UX tasks"),
                ],
            ),
        ],
    ),
    (
        "MarketplaceAndDiscovery",
        "Marketplace and discovery",
        [
            (
                "ApiAndModelMarketplaces",
                "API and model marketplaces",
                [
                    ("HostedModelEndpointsListing", "Hosted model endpoints listing"),
                    ("ApiProductSubscriptions", "API product subscriptions"),
                    ("PrivateOfferNegotiation", "Private offer negotiation"),
                ],
            ),
            (
                "DataProductMarketplaces",
                "Data product marketplaces",
                [
                    ("DatasetListings", "Dataset listings"),
                    ("StreamAndFeedSubscriptions", "Stream and feed subscriptions"),
                    ("DataLicensingTerms", "Data licensing terms"),
                ],
            ),
            (
                "AgentAndPluginDirectories",
                "Agent and plugin directories",
                [
                    ("McpAndToolPlugins", "MCP and tool plugins"),
                    ("AgentSkillPacks", "Agent skill packs"),
                    ("WorkflowTemplateMarketplace", "Workflow template marketplace"),
                ],
            ),
            (
                "LeadGenerationAndDemandGen",
                "Lead generation and demand gen",
                [
                    ("B2bLeadLists", "B2B lead lists"),
                    ("IntentSignalFeeds", "Intent signal feeds"),
                    ("AppointmentSettingServices", "Appointment setting services"),
                ],
            ),
            (
                "SupplyAndWholesaleAccess",
                "Supply and wholesale access",
                [
                    ("WholesaleCatalogAccess", "Wholesale catalog access"),
                    ("DropShipSupplierNetworks", "Drop-ship supplier networks"),
                    ("ProcurementRfqMatching", "Procurement RFQ matching"),
                ],
            ),
            (
                "AdvertisingAndSponsoredPlacement",
                "Advertising and sponsored placement",
                [
                    ("SponsoredSearchResults", "Sponsored search results"),
                    ("CategoryFeaturedListings", "Category featured listings"),
                    ("RetargetingAndAttributionApis", "Retargeting / attribution APIs"),
                ],
            ),
            (
                "AuctionsAndDynamicMarkets",
                "Auctions and dynamic markets",
                [
                    ("SpotAuctionVenues", "Spot auction venues"),
                    ("ReverseAuctionPlatforms", "Reverse auction platforms"),
                    ("ExchangeStyleOrderBooks", "Exchange-style order books"),
                ],
            ),
        ],
    ),
    (
        "PhysicalGoodsAndLogistics",
        "Physical goods and logistics",
        [
            (
                "RawMaterialsAndComponents",
                "Raw materials and components",
                [
                    ("CommodityInputs", "Commodity inputs"),
                    ("ElectronicComponents", "Electronic components"),
                    ("CustomManufacturedParts", "Custom manufactured parts"),
                ],
            ),
            (
                "FinishedGoodsAndRetailProducts",
                "Finished goods and retail products",
                [
                    ("ConsumerPackagedGoods", "Consumer packaged goods"),
                    ("DurableGoods", "Durable goods"),
                    ("PrivateLabelSku", "Private label SKU"),
                ],
            ),
            (
                "PackagingAndConsumables",
                "Packaging and consumables",
                [
                    ("ShippingPackagingSupplies", "Shipping packaging supplies"),
                    ("MroConsumables", "MRO consumables"),
                    ("ColdChainSupplies", "Cold chain supplies"),
                ],
            ),
            (
                "WarehousingAndFulfillment",
                "Warehousing and fulfillment",
                [
                    ("PickPackShip3pl", "Pick/pack/ship 3PL"),
                    ("CrossDockTransload", "Cross-dock / transload"),
                    ("KittingAndAssembly", "Kitting and assembly"),
                ],
            ),
            (
                "FreightAndCargo",
                "Freight and cargo",
                [
                    ("FullTruckloadLtl", "Full truckload / LTL"),
                    ("AirAndOceanFreight", "Air and ocean freight"),
                    ("FreightForwarding", "Freight forwarding"),
                ],
            ),
            (
                "LastMileDelivery",
                "Last-mile delivery",
                [
                    ("CourierSameDay", "Courier / same-day"),
                    ("ParcelLockerDelivery", "Parcel locker delivery"),
                    ("WhiteGloveDelivery", "White glove delivery"),
                ],
            ),
            (
                "ReturnsAndReverseLogistics",
                "Returns and reverse logistics",
                [
                    ("RmaProcessing", "RMA processing"),
                    ("RefurbishmentAndGrading", "Refurbishment and grading"),
                    ("LiquidationChannels", "Liquidation channels"),
                ],
            ),
            (
                "CustomsAndCrossBorder",
                "Customs and cross-border",
                [
                    ("CustomsBrokerage", "Customs brokerage"),
                    ("DutiesAndTaxEstimation", "Duties and tax estimation"),
                    ("ExportComplianceScreening", "Export compliance screening"),
                ],
            ),
        ],
    ),
    (
        "TrustRiskAndCompliance",
        "Trust, risk, and compliance",
        [
            (
                "ConsumerIdentityKyc",
                "Consumer identity (KYC)",
                [
                    ("DocumentIdVerification", "Document ID verification"),
                    ("BiometricLivenessChecks", "Biometric liveness checks"),
                    ("AddressAndPhoneVerification", "Address and phone verification"),
                ],
            ),
            (
                "BusinessIdentityKyb",
                "Business identity (KYB)",
                [
                    ("CompanyRegistryLookup", "Company registry lookup"),
                    ("BeneficialOwnershipGraph", "Beneficial ownership graph"),
                    ("UboAttestation", "UBO attestation"),
                ],
            ),
            (
                "FraudAndRiskSignals",
                "Fraud and risk signals",
                [
                    ("TransactionRiskScoring", "Transaction risk scoring"),
                    ("DeviceAndBehaviorRisk", "Device and behavior risk"),
                    ("AccountTakeoverSignals", "Account takeover signals"),
                ],
            ),
            (
                "SanctionsAndWatchlists",
                "Sanctions and watchlists",
                [
                    ("SanctionsScreeningApi", "Sanctions screening API"),
                    ("PepAndAdverseMedia", "PEP and adverse media"),
                    ("OngoingMonitoringAlerts", "Ongoing monitoring alerts"),
                ],
            ),
            (
                "AuditAttestationAndEvidence",
                "Audit, attestation, and evidence",
                [
                    ("TimestampingAndHashAnchoring", "Timestamping / hash anchoring"),
                    ("ThirdPartyAttestationReports", "Third-party attestation reports"),
                    ("ImmutableLogExport", "Immutable log export"),
                ],
            ),
            (
                "ContentProvenanceAndIntegrity",
                "Content provenance and integrity",
                [
                    ("C2paAndContentCredentials", "C2PA / content credentials"),
                    ("SyntheticMediaDetection", "Synthetic media detection"),
                    ("WatermarkingAndFingerprinting", "Watermarking / fingerprinting"),
                ],
            ),
            (
                "ContractSignatureAndLegalWorkflow",
                "Contract signature and legal workflow",
                [
                    ("ESignaturePlatforms", "E-signature platforms"),
                    ("ClauseAndTemplateLibraries", "Clause and template libraries"),
                    ("ContractLifecycleAlerts", "Contract lifecycle alerts"),
                ],
            ),
            (
                "InsuranceAndSuretyServices",
                "Insurance and surety services",
                [
                    ("TransactionInsurance", "Transaction insurance"),
                    ("SuretyAndPerformanceBonds", "Surety / performance bonds"),
                    ("ShippingAndCargoInsurance", "Shipping / cargo insurance"),
                ],
            ),
        ],
    ),
]


def ttl_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main() -> None:
    def h(loc: str) -> str:
        """Hash vocabulary term: <#LocalName> against @base <BASE>."""
        return f"<#{loc}>"

    has_top = " ,\n  ".join(h(t[0]) for t in HIERARCHY)
    lines = [
        f"# Concept IRIs: <#LocalName> with @base <{BASE}> → {BASE}#LocalName",
        f"@base <{BASE}> .",
        "@prefix skos: <http://www.w3.org/2004/02/skos/core#> .",
        "@prefix dct: <http://purl.org/dc/terms/> .",
        "@prefix owl: <http://www.w3.org/2002/07/owl#> .",
        f"@prefix agcs: <{SCHEME_PREFIX}> .",
        "",
        "agcs:AgentServiceCategory a skos:ConceptScheme ;",
        '  dct:title "AVP-Micro agent service categories"@en ;',
        '  dct:description "Three-level SKOS hierarchy for classifying paid services in agent commerce (informative vocabulary)."@en ;',
        f'  owl:versionInfo "0.1.0" ;',
        f"  skos:hasTopConcept\n  {has_top} .",
        "",
    ]

    for top_id, top_label, l2_list in HIERARCHY:
        lines.append(f"{h(top_id)} a skos:Concept ;")
        lines.append(f'  skos:prefLabel "{ttl_escape(top_label)}"@en ;')
        lines.append(f'  skos:notation "{top_id}" ;')
        lines.append("  skos:topConceptOf agcs:AgentServiceCategory ;")
        lines.append("  skos:inScheme agcs:AgentServiceCategory .")
        lines.append("")

        for l2_id, l2_label, leaves in l2_list:
            lines.append(f"{h(l2_id)} a skos:Concept ;")
            lines.append(f'  skos:prefLabel "{ttl_escape(l2_label)}"@en ;')
            lines.append(f'  skos:notation "{l2_id}" ;')
            lines.append(f"  skos:broader {h(top_id)} ;")
            lines.append("  skos:inScheme agcs:AgentServiceCategory .")
            lines.append("")

            for leaf_id, leaf_label in leaves:
                lines.append(f"{h(leaf_id)} a skos:Concept ;")
                lines.append(f'  skos:prefLabel "{ttl_escape(leaf_label)}"@en ;')
                lines.append(f'  skos:notation "{leaf_id}" ;')
                lines.append(f"  skos:broader {h(l2_id)} ;")
                lines.append("  skos:inScheme agcs:AgentServiceCategory .")
                lines.append("")

        narrowers = " ,\n    ".join(h(l2_id) for l2_id, _, _ in l2_list)
        lines.append(f"{h(top_id)} skos:narrower")
        lines.append(f"    {narrowers} .")
        lines.append("")

        for l2_id, _, leaves in l2_list:
            if not leaves:
                continue
            leaf_uris = " ,\n    ".join(h(lid) for lid, _ in leaves)
            lines.append(f"{h(l2_id)} skos:narrower")
            lines.append(f"    {leaf_uris} .")
            lines.append("")

    out = Path(__file__).with_name("agent-service-categories.ttl")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out} ({len(lines)} lines)")


if __name__ == "__main__":
    main()
