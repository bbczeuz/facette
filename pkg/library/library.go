// Package library implements the service library handling user-defined items (e.g. sources and metrics groups, graphs,
// collections).
package library

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/facette/facette/pkg/catalog"
	"github.com/facette/facette/pkg/config"
	"github.com/facette/facette/pkg/logger"
	"github.com/facette/facette/pkg/utils"
)

const (
	_ = iota
	// LibraryItemSourceGroup represents a source group item.
	LibraryItemSourceGroup
	// LibraryItemMetricGroup represents a metric group item.
	LibraryItemMetricGroup
	// LibraryItemUnit represents an unit item.
	LibraryItemUnit
	// LibraryItemScale represents a scale item.
	LibraryItemScale
	// LibraryItemGraph represents a graph item.
	LibraryItemGraph
	// LibraryItemCollection represents a collection item.
	LibraryItemCollection
)

const (
	// UUIDPattern represents an UUID validation pattern.
	UUIDPattern = "^\\d{8}-(?:\\d{4}-){3}\\d{12}$"
)

// Library represents the main structure of library instance.
type Library struct {
	Config      *config.Config
	Catalog     *catalog.Catalog
	Groups      map[string]*Group
	Scales      map[string]*Scale
	Units       map[string]*Unit
	Graphs      map[string]*Graph
	Collections map[string]*Collection
	idRegexp    *regexp.Regexp
}

// NewLibrary creates a new instance of library.
func NewLibrary(config *config.Config, catalog *catalog.Catalog) *Library {
	return &Library{
		Config:   config,
		Catalog:  catalog,
		idRegexp: regexp.MustCompile(UUIDPattern),
	}
}

// Refresh updates the current library by browsing the filesystem for stored data.
func (library *Library) Refresh() error {
	var itemType int

	// Empty library maps
	library.Groups = make(map[string]*Group)
	library.Scales = make(map[string]*Scale)
	library.Units = make(map[string]*Unit)
	library.Graphs = make(map[string]*Graph)
	library.Collections = make(map[string]*Collection)

	walkFunc := func(filePath string, fileInfo os.FileInfo, fileError error) error {
		mode := fileInfo.Mode() & os.ModeType
		if mode != 0 || !strings.HasSuffix(filePath, ".json") {
			return nil
		}

		_, itemID := path.Split(filePath[:len(filePath)-5])

		logger.Log(logger.LevelDebug, "library", "loading item `%s' from file `%s'", itemID, filePath)

		return library.LoadItem(itemID, itemType)
	}

	logger.Log(logger.LevelInfo, "library", "refresh started")

	for _, itemType = range []int{
		LibraryItemSourceGroup,
		LibraryItemMetricGroup,
		LibraryItemScale,
		LibraryItemUnit,
		LibraryItemGraph,
		LibraryItemCollection,
	} {
		dirPath := library.getDirPath(itemType)

		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		if err := utils.WalkDir(dirPath, walkFunc); err != nil {
			logger.Log(logger.LevelError, "library", "%s", err)
		}
	}

	// Update collection items parent-children relations
	for _, collection := range library.Collections {
		if collection.ParentID == "" {
			continue
		}

		if _, ok := library.Collections[collection.ParentID]; !ok {
			logger.Log(logger.LevelError, "library", "unknown parent identifier `%s'", collection.ParentID)
			continue
		}

		collection.Parent = library.Collections[collection.ParentID]
		collection.Parent.Children = append(collection.Parent.Children, collection)
	}

	logger.Log(logger.LevelInfo, "library", "refresh completed")

	return nil
}

// CreateGraph registers a new graph to the library
func (library *Library) CreateGraph(def []byte, graph *Graph) (*Graph, error) {
	if graph == nil {
		graph = &Graph{}
	}

	if err := json.Unmarshal(def, graph); err != nil {
		return nil, fmt.Errorf("unable to unmarshal graph definition: %s", err)
	}

	if err := library.StoreItem(graph, LibraryItemGraph); err != nil {
		return nil, fmt.Errorf("unable to store graph: %s", err)
	}

	return graph, nil
}

// UpdateGraph updates an existing graph
func (library *Library) UpdateGraph(def []byte, id string) (*Graph, error) {
	if id == "" {
		return nil, fmt.Errorf("no graph ID provided")
	}

	graph, err := library.GetItem(id, LibraryItemGraph)
	if err != nil {
		return nil, fmt.Errorf("graph not found")
	}

	return library.CreateGraph(def, graph.(*Graph))
}

// CloneGraph clones an existing graph
func (library *Library) CloneGraph(def []byte, source string) (*Graph, error) {
	sourceGraph, err := library.GetItem(source, LibraryItemGraph)
	if err != nil {
		return nil, fmt.Errorf("source graph not found")
	}

	graph := &Graph{}
	utils.Clone(sourceGraph.(*Graph), graph)

	// Reset graph ID
	graph.ID = ""

	return library.CreateGraph(def, graph)
}
